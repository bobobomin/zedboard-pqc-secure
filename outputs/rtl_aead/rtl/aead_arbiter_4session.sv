`timescale 1ns/1ps

/*
 * Four-session, one-engine AEAD request arbiter.
 *
 * Each request port corresponds to one session-table slot. Requests are
 * selected round-robin. A session entry stores independent TX/RX keys,
 * nonce prefixes, and counters. RX accepts only the next expected counter.
 */
module aead_arbiter_4session (
    input  logic          clk_i,
    input  logic          rst_ni,

    input  logic          cfg_write_i,
    input  logic [1:0]    cfg_slot_i,
    input  logic          cfg_valid_i,
    input  logic [31:0]   cfg_session_id_i,
    input  logic [255:0]  cfg_tx_key_i,
    input  logic [255:0]  cfg_rx_key_i,
    input  logic [31:0]   cfg_tx_nonce_prefix_i,
    input  logic [31:0]   cfg_rx_nonce_prefix_i,
    output logic          cfg_ready_o,

    input  logic [3:0]    req_valid_i,
    output logic [3:0]    req_ready_o,
    input  logic [3:0]    req_decrypt_i,
    input  logic [31:0]   req_data_len_i,
    input  logic [255:0]  req_counter_i,
    input  logic [2047:0] req_data_i,
    input  logic [511:0]  req_tag_i,

    output logic [3:0]    rsp_valid_o,
    input  logic [3:0]    rsp_ready_i,
    output logic [3:0]    rsp_auth_ok_o,
    output logic [3:0]    rsp_error_o,
    output logic [255:0]  rsp_counter_o,
    output logic [2047:0] rsp_data_o,
    output logic [511:0]  rsp_tag_o
);

    typedef enum logic [1:0] {
        A_IDLE,
        A_WAIT_ENGINE,
        A_RESPONSE
    } arb_state_t;

    arb_state_t state;

    logic         session_valid [0:3];
    logic [31:0]  session_id    [0:3];
    logic [255:0] tx_key        [0:3];
    logic [255:0] rx_key        [0:3];
    logic [31:0]  tx_prefix     [0:3];
    logic [31:0]  rx_prefix     [0:3];
    logic [63:0]  tx_counter    [0:3];
    logic [63:0]  rx_counter    [0:3];

    logic [1:0] last_grant;
    logic [1:0] grant_slot;
    logic       grant_valid;
    logic [1:0] active_slot;
    logic       active_decrypt;
    logic [63:0] active_counter;

    logic         engine_start;
    logic         engine_decrypt;
    logic [255:0] engine_key;
    logic [95:0]  engine_nonce;
    logic [127:0] engine_aad;
    logic [511:0] engine_data_in;
    logic [127:0] engine_received_tag;
    logic         engine_done;
    logic         engine_auth_ok;
    logic [511:0] engine_data_out;
    logic [127:0] engine_tag_out;

    integer reset_index;

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

    /* Round-robin priority begins immediately after the previous winner. */
    always_comb begin
        grant_slot  = 2'd0;
        grant_valid = 1'b0;
        case (last_grant)
            2'd0: begin
                if      (req_valid_i[1]) begin grant_slot=2'd1; grant_valid=1'b1; end
                else if (req_valid_i[2]) begin grant_slot=2'd2; grant_valid=1'b1; end
                else if (req_valid_i[3]) begin grant_slot=2'd3; grant_valid=1'b1; end
                else if (req_valid_i[0]) begin grant_slot=2'd0; grant_valid=1'b1; end
            end
            2'd1: begin
                if      (req_valid_i[2]) begin grant_slot=2'd2; grant_valid=1'b1; end
                else if (req_valid_i[3]) begin grant_slot=2'd3; grant_valid=1'b1; end
                else if (req_valid_i[0]) begin grant_slot=2'd0; grant_valid=1'b1; end
                else if (req_valid_i[1]) begin grant_slot=2'd1; grant_valid=1'b1; end
            end
            2'd2: begin
                if      (req_valid_i[3]) begin grant_slot=2'd3; grant_valid=1'b1; end
                else if (req_valid_i[0]) begin grant_slot=2'd0; grant_valid=1'b1; end
                else if (req_valid_i[1]) begin grant_slot=2'd1; grant_valid=1'b1; end
                else if (req_valid_i[2]) begin grant_slot=2'd2; grant_valid=1'b1; end
            end
            default: begin
                if      (req_valid_i[0]) begin grant_slot=2'd0; grant_valid=1'b1; end
                else if (req_valid_i[1]) begin grant_slot=2'd1; grant_valid=1'b1; end
                else if (req_valid_i[2]) begin grant_slot=2'd2; grant_valid=1'b1; end
                else if (req_valid_i[3]) begin grant_slot=2'd3; grant_valid=1'b1; end
            end
        endcase
    end

    always_comb begin
        req_ready_o = 4'b0000;
        cfg_ready_o = (state == A_IDLE);
        if ((state == A_IDLE) && !cfg_write_i && grant_valid)
            req_ready_o[grant_slot] = 1'b1;
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
            state               <= A_IDLE;
            last_grant          <= 2'd3;
            active_slot         <= '0;
            active_decrypt      <= 1'b0;
            active_counter      <= '0;
            engine_start        <= 1'b0;
            engine_decrypt      <= 1'b0;
            engine_key          <= '0;
            engine_nonce        <= '0;
            engine_aad          <= '0;
            engine_data_in      <= '0;
            engine_received_tag <= '0;
            rsp_valid_o         <= '0;
            rsp_auth_ok_o       <= '0;
            rsp_error_o         <= '0;
            rsp_counter_o       <= '0;
            rsp_data_o          <= '0;
            rsp_tag_o           <= '0;
            for (reset_index = 0; reset_index < 4; reset_index = reset_index + 1) begin
                session_valid[reset_index] <= 1'b0;
                session_id[reset_index]    <= '0;
                tx_key[reset_index]        <= '0;
                rx_key[reset_index]        <= '0;
                tx_prefix[reset_index]     <= '0;
                rx_prefix[reset_index]     <= '0;
                tx_counter[reset_index]    <= '0;
                rx_counter[reset_index]    <= '0;
            end
        end else begin
            engine_start <= 1'b0;

            case (state)
                A_IDLE: begin
                    if (cfg_write_i) begin
                        session_valid[cfg_slot_i] <= cfg_valid_i;
                        session_id[cfg_slot_i]    <= cfg_session_id_i;
                        tx_key[cfg_slot_i]        <= cfg_tx_key_i;
                        rx_key[cfg_slot_i]        <= cfg_rx_key_i;
                        tx_prefix[cfg_slot_i]     <= cfg_tx_nonce_prefix_i;
                        rx_prefix[cfg_slot_i]     <= cfg_rx_nonce_prefix_i;
                        tx_counter[cfg_slot_i]    <= 64'd0;
                        rx_counter[cfg_slot_i]    <= 64'd0;
                    end else if (grant_valid) begin
                        active_slot    <= grant_slot;
                        active_decrypt <= req_decrypt_i[grant_slot];
                        last_grant     <= grant_slot;

                        if (req_decrypt_i[grant_slot])
                            active_counter <= req_counter_i[64*grant_slot +: 64];
                        else
                            active_counter <= tx_counter[grant_slot];

                        if (!session_valid[grant_slot]
                            || (req_data_len_i[8*grant_slot +: 8] > 8'd64)
                            || (req_decrypt_i[grant_slot]
                                && req_counter_i[64*grant_slot +: 64]
                                   != rx_counter[grant_slot])) begin
                            rsp_data_o[512*grant_slot +: 512]    <= '0;
                            rsp_tag_o[128*grant_slot +: 128]     <= '0;
                            rsp_counter_o[64*grant_slot +: 64]   <=
                                req_decrypt_i[grant_slot]
                                ? req_counter_i[64*grant_slot +: 64] : 64'd0;
                            rsp_auth_ok_o[grant_slot] <= 1'b0;
                            rsp_error_o[grant_slot]   <= 1'b1;
                            rsp_valid_o[grant_slot]   <= 1'b1;
                            state <= A_RESPONSE;
                        end else begin
                            engine_decrypt <= req_decrypt_i[grant_slot];
                            engine_key <= req_decrypt_i[grant_slot]
                                        ? rx_key[grant_slot] : tx_key[grant_slot];
                            engine_nonce[31:0] <= req_decrypt_i[grant_slot]
                                                   ? rx_prefix[grant_slot]
                                                   : tx_prefix[grant_slot];
                            engine_nonce[95:32] <= pack64_be(
                                req_decrypt_i[grant_slot]
                                ? req_counter_i[64*grant_slot +: 64]
                                : tx_counter[grant_slot]);
                            engine_aad <= '0;
                            engine_aad[31:0] <= pack32_be(session_id[grant_slot]);
                            engine_aad[95:32] <= pack64_be(
                                req_decrypt_i[grant_slot]
                                ? req_counter_i[64*grant_slot +: 64]
                                : tx_counter[grant_slot]);
                            engine_aad[103:96] <= req_data_len_i[8*grant_slot +: 8];
                            engine_data_in <= req_data_i[512*grant_slot +: 512];
                            engine_received_tag <= req_tag_i[128*grant_slot +: 128];
                            engine_start <= 1'b1;
                            state <= A_WAIT_ENGINE;
                        end
                    end
                end

                A_WAIT_ENGINE: begin
                    if (engine_done) begin
                        rsp_data_o[512*active_slot +: 512]  <= engine_data_out;
                        rsp_tag_o[128*active_slot +: 128]   <= engine_tag_out;
                        rsp_counter_o[64*active_slot +: 64] <= active_counter;
                        rsp_auth_ok_o[active_slot] <= engine_auth_ok;
                        rsp_error_o[active_slot]   <= !engine_auth_ok;
                        rsp_valid_o[active_slot]   <= 1'b1;

                        if (!active_decrypt && engine_auth_ok)
                            tx_counter[active_slot] <= tx_counter[active_slot] + 64'd1;
                        else if (active_decrypt && engine_auth_ok)
                            rx_counter[active_slot] <= rx_counter[active_slot] + 64'd1;
                        state <= A_RESPONSE;
                    end
                end

                A_RESPONSE: begin
                    if (rsp_ready_i[active_slot]) begin
                        rsp_valid_o[active_slot] <= 1'b0;
                        state <= A_IDLE;
                    end
                end

                default: state <= A_IDLE;
            endcase
        end
    end

endmodule
