`timescale 1ns/1ps

/*
 * Indexed AEAD session manager for PS-scheduled traffic.
 *
 * Session state is stored as 24 32-bit words per slot so that increasing the
 * number of logical clients grows BRAM depth instead of creating per-client
 * packet buses and wide key multiplexers.  The PS submits one request at a
 * time together with its slot index; fairness/queuing therefore belongs to
 * PS software rather than this block.
 */
module aead_session_manager_bram #(
    parameter integer NUM_SESSIONS = 64,
    parameter integer SLOT_WIDTH = $clog2(NUM_SESSIONS)
)(
    input  logic                    clk_i,
    input  logic                    rst_ni,

    input  logic                    cfg_write_i,
    input  logic [SLOT_WIDTH-1:0]   cfg_slot_i,
    input  logic                    cfg_valid_i,
    input  logic [31:0]             cfg_session_id_i,
    input  logic [255:0]            cfg_tx_key_i,
    input  logic [255:0]            cfg_rx_key_i,
    input  logic [31:0]             cfg_tx_nonce_prefix_i,
    input  logic [31:0]             cfg_rx_nonce_prefix_i,
    output logic                    cfg_ready_o,
    output logic                    cfg_done_o,

    input  logic                    req_valid_i,
    output logic                    req_ready_o,
    input  logic [SLOT_WIDTH-1:0]   req_slot_i,
    input  logic                    req_decrypt_i,
    input  logic [7:0]              req_data_len_i,
    input  logic [63:0]             req_counter_i,
    input  logic [511:0]            req_data_i,
    input  logic [127:0]            req_tag_i,

    output logic                    rsp_valid_o,
    input  logic                    rsp_ready_i,
    output logic                    rsp_auth_ok_o,
    output logic                    rsp_error_o,
    output logic [SLOT_WIDTH-1:0]   rsp_slot_o,
    output logic [63:0]             rsp_counter_o,
    output logic [511:0]            rsp_data_o,
    output logic [127:0]            rsp_tag_o
);
    localparam integer WORDS_PER_SESSION = 24;
    localparam integer MEM_WORDS = NUM_SESSIONS * WORDS_PER_SESSION;
    localparam integer MEM_ADDR_WIDTH = $clog2(MEM_WORDS);

    localparam logic [4:0] WORD_SESSION_ID = 5'd0;
    localparam logic [4:0] WORD_TX_KEY_0   = 5'd1;
    localparam logic [4:0] WORD_RX_KEY_0   = 5'd9;
    localparam logic [4:0] WORD_TX_PREFIX  = 5'd17;
    localparam logic [4:0] WORD_RX_PREFIX  = 5'd18;
    localparam logic [4:0] WORD_TX_COUNT_LO = 5'd19;
    localparam logic [4:0] WORD_TX_COUNT_HI = 5'd20;
    localparam logic [4:0] WORD_RX_COUNT_LO = 5'd21;
    localparam logic [4:0] WORD_RX_COUNT_HI = 5'd22;
    localparam logic [4:0] WORD_RESERVED    = 5'd23;

    typedef enum logic [3:0] {
        S_IDLE,
        S_CFG_WRITE,
        S_READ_ISSUE,
        S_READ_CAPTURE,
        S_CHECK,
        S_ENGINE_WAIT,
        S_COUNT_WRITE_LO,
        S_COUNT_WRITE_HI,
        S_RESPONSE
    } state_t;

    state_t state;

    (* ram_style = "block" *) logic [31:0] session_mem [0:MEM_WORDS-1];
    logic [NUM_SESSIONS-1:0] session_valid;
    logic [31:0] mem_rdata;
    logic mem_write_enable, mem_read_enable;
    logic [MEM_ADDR_WIDTH-1:0] mem_access_addr;
    logic [31:0] mem_write_data;

    logic [MEM_ADDR_WIDTH-1:0] cfg_base_q;
    logic [4:0] cfg_word_q;
    logic [31:0] cfg_session_id_q;
    logic [255:0] cfg_tx_key_q, cfg_rx_key_q;
    logic [31:0] cfg_tx_prefix_q, cfg_rx_prefix_q;
    logic [SLOT_WIDTH-1:0] cfg_slot_q;

    logic [MEM_ADDR_WIDTH-1:0] active_base_q;
    logic [4:0] read_word_q;
    logic [SLOT_WIDTH-1:0] active_slot_q;
    logic active_decrypt_q;
    logic [7:0] active_len_q;
    logic [63:0] request_counter_q;
    logic [511:0] request_data_q;
    logic [127:0] request_tag_q;

    logic [31:0] active_session_id;
    logic [255:0] active_tx_key, active_rx_key;
    logic [31:0] active_tx_prefix, active_rx_prefix;
    logic [63:0] active_tx_counter, active_rx_counter;
    logic [63:0] operation_counter_q, updated_counter_q;
    logic [4:0] counter_word_lo_q, counter_word_hi_q;

    logic engine_start, engine_decrypt;
    logic [255:0] engine_key;
    logic [95:0] engine_nonce;
    logic [127:0] engine_aad;
    logic [511:0] engine_data_in;
    logic [127:0] engine_received_tag;
    logic engine_done, engine_auth_ok;
    logic [511:0] engine_data_out;
    logic [127:0] engine_tag_out;

    function automatic logic slot_in_range(input logic [SLOT_WIDTH-1:0] slot);
        slot_in_range = (slot < NUM_SESSIONS);
    endfunction

    function automatic logic [MEM_ADDR_WIDTH-1:0] slot_base(
        input logic [SLOT_WIDTH-1:0] slot);
        slot_base = slot * WORDS_PER_SESSION;
    endfunction

    function automatic logic [31:0] config_word(input logic [4:0] word_index);
        begin
            if (word_index == WORD_SESSION_ID)
                config_word = cfg_session_id_q;
            else if ((word_index >= WORD_TX_KEY_0) && (word_index < WORD_RX_KEY_0))
                config_word = cfg_tx_key_q[32*(word_index-WORD_TX_KEY_0) +: 32];
            else if ((word_index >= WORD_RX_KEY_0) && (word_index < WORD_TX_PREFIX))
                config_word = cfg_rx_key_q[32*(word_index-WORD_RX_KEY_0) +: 32];
            else if (word_index == WORD_TX_PREFIX)
                config_word = cfg_tx_prefix_q;
            else if (word_index == WORD_RX_PREFIX)
                config_word = cfg_rx_prefix_q;
            else
                config_word = 32'd0;
        end
    endfunction

    function automatic logic [31:0] pack32_be(input logic [31:0] value);
        integer j;
        begin
            for (j = 0; j < 4; j = j + 1)
                pack32_be[8*j +: 8] = value[31-8*j -: 8];
        end
    endfunction

    function automatic logic [63:0] pack64_be(input logic [63:0] value);
        integer j;
        begin
            for (j = 0; j < 8; j = j + 1)
                pack64_be[8*j +: 8] = value[63-8*j -: 8];
        end
    endfunction

    assign cfg_ready_o = (state == S_IDLE);
    assign req_ready_o = (state == S_IDLE) && !cfg_write_i;

    always_comb begin
        mem_write_enable = 1'b0;
        mem_read_enable  = 1'b0;
        mem_access_addr  = '0;
        mem_write_data   = 32'd0;

        case (state)
            S_CFG_WRITE: begin
                mem_write_enable = 1'b1;
                mem_access_addr  = cfg_base_q + cfg_word_q;
                mem_write_data   = config_word(cfg_word_q);
            end
            S_READ_ISSUE: begin
                mem_read_enable = 1'b1;
                mem_access_addr = active_base_q + read_word_q;
            end
            S_COUNT_WRITE_LO: begin
                mem_write_enable = 1'b1;
                mem_access_addr  = active_base_q + counter_word_lo_q;
                mem_write_data   = updated_counter_q[31:0];
            end
            S_COUNT_WRITE_HI: begin
                mem_write_enable = 1'b1;
                mem_access_addr  = active_base_q + counter_word_hi_q;
                mem_write_data   = updated_counter_q[63:32];
            end
            default: begin end
        endcase
    end

    /* No reset on the RAM process: resetting the memory prevents BRAM inference. */
    always_ff @(posedge clk_i) begin
        if (mem_write_enable)
            session_mem[mem_access_addr] <= mem_write_data;
        if (mem_read_enable)
            mem_rdata <= session_mem[mem_access_addr];
    end

    aead_fixed64_engine u_engine (
        .clk_i(clk_i), .rst_ni(rst_ni), .start_i(engine_start),
        .decrypt_i(engine_decrypt), .key_i(engine_key),
        .nonce_i(engine_nonce), .aad_i(engine_aad),
        .data_i(engine_data_in), .received_tag_i(engine_received_tag),
        .busy_o(), .done_o(engine_done), .auth_ok_o(engine_auth_ok),
        .data_o(engine_data_out), .tag_o(engine_tag_out)
    );

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state                 <= S_IDLE;
            session_valid         <= '0;
            cfg_done_o            <= 1'b0;
            cfg_base_q            <= '0;
            cfg_word_q            <= '0;
            cfg_session_id_q      <= '0;
            cfg_tx_key_q          <= '0;
            cfg_rx_key_q          <= '0;
            cfg_tx_prefix_q       <= '0;
            cfg_rx_prefix_q       <= '0;
            cfg_slot_q            <= '0;
            active_base_q         <= '0;
            read_word_q           <= '0;
            active_slot_q         <= '0;
            active_decrypt_q      <= 1'b0;
            active_len_q          <= '0;
            request_counter_q     <= '0;
            request_data_q        <= '0;
            request_tag_q         <= '0;
            active_session_id     <= '0;
            active_tx_key         <= '0;
            active_rx_key         <= '0;
            active_tx_prefix      <= '0;
            active_rx_prefix      <= '0;
            active_tx_counter     <= '0;
            active_rx_counter     <= '0;
            operation_counter_q   <= '0;
            updated_counter_q     <= '0;
            counter_word_lo_q     <= '0;
            counter_word_hi_q     <= '0;
            engine_start          <= 1'b0;
            engine_decrypt        <= 1'b0;
            engine_key            <= '0;
            engine_nonce          <= '0;
            engine_aad            <= '0;
            engine_data_in        <= '0;
            engine_received_tag   <= '0;
            rsp_valid_o           <= 1'b0;
            rsp_auth_ok_o         <= 1'b0;
            rsp_error_o           <= 1'b0;
            rsp_slot_o            <= '0;
            rsp_counter_o         <= '0;
            rsp_data_o            <= '0;
            rsp_tag_o             <= '0;
        end else begin
            cfg_done_o   <= 1'b0;
            engine_start <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (cfg_write_i) begin
                        if (!slot_in_range(cfg_slot_i)) begin
                            cfg_done_o <= 1'b1;
                        end else if (!cfg_valid_i) begin
                            session_valid[cfg_slot_i] <= 1'b0;
                            cfg_done_o <= 1'b1;
                        end else begin
                            cfg_slot_q       <= cfg_slot_i;
                            cfg_base_q       <= slot_base(cfg_slot_i);
                            cfg_word_q       <= 5'd0;
                            cfg_session_id_q <= cfg_session_id_i;
                            cfg_tx_key_q     <= cfg_tx_key_i;
                            cfg_rx_key_q     <= cfg_rx_key_i;
                            cfg_tx_prefix_q  <= cfg_tx_nonce_prefix_i;
                            cfg_rx_prefix_q  <= cfg_rx_nonce_prefix_i;
                            state            <= S_CFG_WRITE;
                        end
                    end else if (req_valid_i) begin
                        active_slot_q     <= req_slot_i;
                        active_decrypt_q  <= req_decrypt_i;
                        active_len_q      <= req_data_len_i;
                        request_counter_q <= req_counter_i;
                        request_data_q    <= req_data_i;
                        request_tag_q     <= req_tag_i;
                        rsp_slot_o        <= req_slot_i;
                        rsp_auth_ok_o     <= 1'b0;
                        rsp_error_o       <= 1'b0;
                        rsp_data_o        <= '0;
                        rsp_tag_o         <= '0;

                        if (!slot_in_range(req_slot_i) || !session_valid[req_slot_i]) begin
                            rsp_counter_o <= req_decrypt_i ? req_counter_i : 64'd0;
                            rsp_error_o   <= 1'b1;
                            rsp_valid_o   <= 1'b1;
                            state         <= S_RESPONSE;
                        end else begin
                            active_base_q     <= slot_base(req_slot_i);
                            read_word_q       <= 5'd0;
                            active_session_id <= '0;
                            active_tx_key     <= '0;
                            active_rx_key     <= '0;
                            active_tx_prefix  <= '0;
                            active_rx_prefix  <= '0;
                            active_tx_counter <= '0;
                            active_rx_counter <= '0;
                            state             <= S_READ_ISSUE;
                        end
                    end
                end

                S_CFG_WRITE: begin
                    if (cfg_word_q == WORD_RESERVED) begin
                        session_valid[cfg_slot_q] <= 1'b1;
                        cfg_done_o                <= 1'b1;
                        state                     <= S_IDLE;
                    end else begin
                        cfg_word_q <= cfg_word_q + 5'd1;
                    end
                end

                S_READ_ISSUE: begin
                    state     <= S_READ_CAPTURE;
                end

                S_READ_CAPTURE: begin
                    if (read_word_q == WORD_SESSION_ID)
                        active_session_id <= mem_rdata;
                    else if ((read_word_q >= WORD_TX_KEY_0) && (read_word_q < WORD_RX_KEY_0))
                        active_tx_key[32*(read_word_q-WORD_TX_KEY_0) +: 32] <= mem_rdata;
                    else if ((read_word_q >= WORD_RX_KEY_0) && (read_word_q < WORD_TX_PREFIX))
                        active_rx_key[32*(read_word_q-WORD_RX_KEY_0) +: 32] <= mem_rdata;
                    else if (read_word_q == WORD_TX_PREFIX)
                        active_tx_prefix <= mem_rdata;
                    else if (read_word_q == WORD_RX_PREFIX)
                        active_rx_prefix <= mem_rdata;
                    else if (read_word_q == WORD_TX_COUNT_LO)
                        active_tx_counter[31:0] <= mem_rdata;
                    else if (read_word_q == WORD_TX_COUNT_HI)
                        active_tx_counter[63:32] <= mem_rdata;
                    else if (read_word_q == WORD_RX_COUNT_LO)
                        active_rx_counter[31:0] <= mem_rdata;
                    else if (read_word_q == WORD_RX_COUNT_HI)
                        active_rx_counter[63:32] <= mem_rdata;

                    if (read_word_q == WORD_RESERVED) begin
                        state <= S_CHECK;
                    end else begin
                        read_word_q <= read_word_q + 5'd1;
                        state       <= S_READ_ISSUE;
                    end
                end

                S_CHECK: begin
                    operation_counter_q <= active_decrypt_q
                                           ? request_counter_q : active_tx_counter;
                    if ((active_len_q > 8'd64)
                        || (active_decrypt_q && (request_counter_q != active_rx_counter))) begin
                        rsp_counter_o <= active_decrypt_q ? request_counter_q : 64'd0;
                        rsp_auth_ok_o <= 1'b0;
                        rsp_error_o   <= 1'b1;
                        rsp_data_o    <= '0;
                        rsp_tag_o     <= '0;
                        rsp_valid_o   <= 1'b1;
                        state         <= S_RESPONSE;
                    end else begin
                        engine_decrypt <= active_decrypt_q;
                        engine_key <= active_decrypt_q ? active_rx_key : active_tx_key;
                        engine_nonce[31:0] <= active_decrypt_q
                                                 ? active_rx_prefix : active_tx_prefix;
                        engine_nonce[95:32] <= pack64_be(active_decrypt_q
                                                 ? request_counter_q : active_tx_counter);
                        engine_aad <= '0;
                        engine_aad[31:0] <= pack32_be(active_session_id);
                        engine_aad[95:32] <= pack64_be(active_decrypt_q
                                                 ? request_counter_q : active_tx_counter);
                        engine_aad[103:96] <= active_len_q;
                        engine_data_in      <= request_data_q;
                        engine_received_tag <= request_tag_q;
                        engine_start        <= 1'b1;
                        state               <= S_ENGINE_WAIT;
                    end
                end

                S_ENGINE_WAIT: begin
                    if (engine_done) begin
                        rsp_counter_o <= operation_counter_q;
                        rsp_auth_ok_o <= engine_auth_ok;
                        rsp_error_o   <= !engine_auth_ok;
                        rsp_data_o    <= engine_auth_ok ? engine_data_out : 512'd0;
                        rsp_tag_o     <= engine_tag_out;

                        if (engine_auth_ok) begin
                            if (active_decrypt_q) begin
                                updated_counter_q <= active_rx_counter + 64'd1;
                                counter_word_lo_q <= WORD_RX_COUNT_LO;
                                counter_word_hi_q <= WORD_RX_COUNT_HI;
                            end else begin
                                updated_counter_q <= active_tx_counter + 64'd1;
                                counter_word_lo_q <= WORD_TX_COUNT_LO;
                                counter_word_hi_q <= WORD_TX_COUNT_HI;
                            end
                            state <= S_COUNT_WRITE_LO;
                        end else begin
                            rsp_valid_o <= 1'b1;
                            state       <= S_RESPONSE;
                        end
                    end
                end

                S_COUNT_WRITE_LO: begin
                    state <= S_COUNT_WRITE_HI;
                end

                S_COUNT_WRITE_HI: begin
                    rsp_valid_o <= 1'b1;
                    state       <= S_RESPONSE;
                end

                S_RESPONSE: begin
                    if (rsp_ready_i) begin
                        rsp_valid_o <= 1'b0;
                        state       <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end
endmodule
