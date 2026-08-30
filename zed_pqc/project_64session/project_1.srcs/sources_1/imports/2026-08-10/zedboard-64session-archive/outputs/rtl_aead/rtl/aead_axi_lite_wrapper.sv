`timescale 1ns/1ps

module aead_axi_lite_wrapper #(
    parameter integer C_S_AXI_ADDR_WIDTH = 10,
    parameter integer C_S_AXI_DATA_WIDTH = 32
) (
    input  logic                              s_axi_aclk,
    input  logic                              s_axi_aresetn,
    input  logic [C_S_AXI_ADDR_WIDTH-1:0]     s_axi_awaddr,
    input  logic                              s_axi_awvalid,
    output logic                              s_axi_awready,
    input  logic [C_S_AXI_DATA_WIDTH-1:0]     s_axi_wdata,
    input  logic [(C_S_AXI_DATA_WIDTH/8)-1:0] s_axi_wstrb,
    input  logic                              s_axi_wvalid,
    output logic                              s_axi_wready,
    output logic [1:0]                        s_axi_bresp,
    output logic                              s_axi_bvalid,
    input  logic                              s_axi_bready,
    input  logic [C_S_AXI_ADDR_WIDTH-1:0]     s_axi_araddr,
    input  logic                              s_axi_arvalid,
    output logic                              s_axi_arready,
    output logic [C_S_AXI_DATA_WIDTH-1:0]     s_axi_rdata,
    output logic [1:0]                        s_axi_rresp,
    output logic                              s_axi_rvalid,
    input  logic                              s_axi_rready
);

    localparam logic [9:0] REG_VERSION          = 10'h000;
    localparam logic [9:0] REG_CONTROL          = 10'h004;
    localparam logic [9:0] REG_STATUS           = 10'h008;
    localparam logic [9:0] REG_REQUEST_SLOT     = 10'h00c;
    localparam logic [9:0] REG_DATA_LEN         = 10'h010;
    localparam logic [9:0] REG_COUNTER_LO       = 10'h014;
    localparam logic [9:0] REG_COUNTER_HI       = 10'h018;
    localparam logic [9:0] REG_RSP_COUNTER_LO   = 10'h01c;
    localparam logic [9:0] REG_RSP_COUNTER_HI   = 10'h020;
    localparam logic [9:0] REG_CFG_SESSION_ID   = 10'h028;
    localparam logic [9:0] REG_CFG_CONTROL      = 10'h02c;
    localparam logic [9:0] REG_TX_KEY_BASE      = 10'h040;
    localparam logic [9:0] REG_RX_KEY_BASE      = 10'h060;
    localparam logic [9:0] REG_TX_PREFIX        = 10'h080;
    localparam logic [9:0] REG_RX_PREFIX        = 10'h084;
    localparam logic [9:0] REG_INPUT_DATA_BASE  = 10'h100;
    localparam logic [9:0] REG_INPUT_TAG_BASE   = 10'h140;
    localparam logic [9:0] REG_OUTPUT_DATA_BASE = 10'h180;
    localparam logic [9:0] REG_OUTPUT_TAG_BASE  = 10'h1c0;
    localparam logic [9:0] REG_KDF_CONTROL      = 10'h200;
    localparam logic [9:0] REG_SHARED_SECRET    = 10'h204;
    localparam logic [9:0] REG_TRANSCRIPT_HASH  = 10'h224;

    logic aw_held, w_held;
    logic [C_S_AXI_ADDR_WIDTH-1:0] awaddr_held;
    logic [31:0] wdata_held;
    logic [3:0]  wstrb_held;
    logic write_commit;

    logic [1:0] request_slot_reg;
    logic [7:0] data_len_reg;
    logic [63:0] counter_reg;
    logic [31:0] cfg_session_id_reg;
    logic [31:0] tx_key_words [0:7];
    logic [31:0] rx_key_words [0:7];
    logic [31:0] tx_prefix_reg, rx_prefix_reg;
    logic [31:0] input_data_words [0:15];
    logic [31:0] input_tag_words [0:3];
    logic [31:0] shared_secret_words [0:7];
    logic [31:0] transcript_hash_words [0:7];
    logic [255:0] kdf_shared_secret,kdf_transcript_hash;
    logic kdf_start,kdf_busy,kdf_done;
    logic [255:0] kdf_pc_key,kdf_zb_key;
    logic [31:0] kdf_pc_prefix,kdf_zb_prefix;

    logic req_issue_pending, req_inflight;
    logic req_decrypt_latched;
    logic [1:0] req_slot_latched;
    logic [7:0] req_len_latched;
    logic [63:0] req_counter_latched;
    logic [511:0] req_data_latched;
    logic [127:0] req_tag_latched;
    logic response_done, response_auth, response_error;
    logic [63:0] response_counter;
    logic [511:0] response_data;
    logic [127:0] response_tag;

    logic cfg_pending;
    logic [1:0] cfg_slot_latched;
    logic cfg_valid_latched;
    logic [31:0] cfg_session_id_latched;
    logic [255:0] cfg_tx_key_latched, cfg_rx_key_latched;
    logic [31:0] cfg_tx_prefix_latched, cfg_rx_prefix_latched;

    logic [3:0] arb_req_valid, arb_req_ready, arb_req_decrypt;
    logic [31:0] arb_req_data_len;
    logic [255:0] arb_req_counter;
    logic [2047:0] arb_req_data;
    logic [511:0] arb_req_tag;
    logic [3:0] arb_rsp_valid, arb_rsp_ready;
    logic [3:0] arb_rsp_auth, arb_rsp_error;
    logic [255:0] arb_rsp_counter;
    logic [2047:0] arb_rsp_data;
    logic [511:0] arb_rsp_tag;
    logic arb_cfg_ready;

    logic [31:0] read_data_mux;
    integer i_read;
    integer i_seq;

    function automatic [31:0] merge_wstrb(
        input logic [31:0] old_value,
        input logic [31:0] new_value,
        input logic [3:0] strobes
    );
        integer b;
        begin
            merge_wstrb = old_value;
            for (b=0; b<4; b=b+1)
                if (strobes[b])
                    merge_wstrb[8*b +: 8] = new_value[8*b +: 8];
        end
    endfunction

    assign s_axi_awready = !aw_held && !s_axi_bvalid;
    assign s_axi_wready  = !w_held  && !s_axi_bvalid;
    assign s_axi_bresp   = 2'b00;
    assign s_axi_arready = !s_axi_rvalid;
    assign s_axi_rresp   = 2'b00;

    /* AXI-Lite channel handling supports independent AW and W arrival. */
    always_ff @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            aw_held       <= 1'b0;
            w_held        <= 1'b0;
            awaddr_held   <= '0;
            wdata_held    <= '0;
            wstrb_held    <= '0;
            write_commit  <= 1'b0;
            s_axi_bvalid  <= 1'b0;
            s_axi_rvalid  <= 1'b0;
            s_axi_rdata   <= '0;
        end else begin
            write_commit <= 1'b0;

            if (s_axi_awvalid && s_axi_awready) begin
                awaddr_held <= s_axi_awaddr;
                aw_held     <= 1'b1;
            end
            if (s_axi_wvalid && s_axi_wready) begin
                wdata_held <= s_axi_wdata;
                wstrb_held <= s_axi_wstrb;
                w_held     <= 1'b1;
            end
            if (aw_held && w_held && !s_axi_bvalid) begin
                write_commit <= 1'b1;
                aw_held      <= 1'b0;
                w_held       <= 1'b0;
                s_axi_bvalid <= 1'b1;
            end else if (s_axi_bvalid && s_axi_bready) begin
                s_axi_bvalid <= 1'b0;
            end

            if (s_axi_arvalid && s_axi_arready) begin
                s_axi_rdata  <= read_data_mux;
                s_axi_rvalid <= 1'b1;
            end else if (s_axi_rvalid && s_axi_rready) begin
                s_axi_rvalid <= 1'b0;
            end
        end
    end

    always_comb begin
        read_data_mux = 32'd0;
        case (s_axi_araddr[9:0])
            REG_VERSION:        read_data_mux = 32'h0001_0000;
            REG_STATUS: begin
                read_data_mux[0] = req_inflight;
                read_data_mux[1] = response_done;
                read_data_mux[2] = response_auth;
                read_data_mux[3] = response_error;
                read_data_mux[4] = cfg_pending;
                read_data_mux[5] = req_issue_pending;
                read_data_mux[6] = kdf_busy;
            end
            REG_REQUEST_SLOT:   read_data_mux = {30'd0, request_slot_reg};
            REG_DATA_LEN:       read_data_mux = {24'd0, data_len_reg};
            REG_COUNTER_LO:     read_data_mux = counter_reg[31:0];
            REG_COUNTER_HI:     read_data_mux = counter_reg[63:32];
            REG_RSP_COUNTER_LO: read_data_mux = response_counter[31:0];
            REG_RSP_COUNTER_HI: read_data_mux = response_counter[63:32];
            REG_CFG_SESSION_ID: read_data_mux = cfg_session_id_reg;
            REG_TX_PREFIX:      read_data_mux = tx_prefix_reg;
            REG_RX_PREFIX:      read_data_mux = rx_prefix_reg;
            default: begin
                for (i_read=0; i_read<8; i_read=i_read+1) begin
                    if (s_axi_araddr[9:0] == REG_TX_KEY_BASE + 4*i_read)
                        read_data_mux = tx_key_words[i_read];
                    if (s_axi_araddr[9:0] == REG_RX_KEY_BASE + 4*i_read)
                        read_data_mux = rx_key_words[i_read];
                    if (s_axi_araddr[9:0] == REG_SHARED_SECRET + 4*i_read)
                        read_data_mux = shared_secret_words[i_read];
                    if (s_axi_araddr[9:0] == REG_TRANSCRIPT_HASH + 4*i_read)
                        read_data_mux = transcript_hash_words[i_read];
                end
                for (i_read=0; i_read<16; i_read=i_read+1) begin
                    if (s_axi_araddr[9:0] == REG_INPUT_DATA_BASE + 4*i_read)
                        read_data_mux = input_data_words[i_read];
                    if (s_axi_araddr[9:0] == REG_OUTPUT_DATA_BASE + 4*i_read)
                        read_data_mux = response_data[32*i_read +: 32];
                end
                for (i_read=0; i_read<4; i_read=i_read+1) begin
                    if (s_axi_araddr[9:0] == REG_INPUT_TAG_BASE + 4*i_read)
                        read_data_mux = input_tag_words[i_read];
                    if (s_axi_araddr[9:0] == REG_OUTPUT_TAG_BASE + 4*i_read)
                        read_data_mux = response_tag[32*i_read +: 32];
                end
            end
        endcase
    end

    always_comb begin
        arb_req_valid    = 4'd0;
        arb_req_decrypt  = 4'd0;
        arb_req_data_len = '0;
        arb_req_counter  = '0;
        arb_req_data     = '0;
        arb_req_tag      = '0;
        if (req_issue_pending) begin
            arb_req_valid[req_slot_latched] = 1'b1;
            arb_req_decrypt[req_slot_latched] = req_decrypt_latched;
            arb_req_data_len[8*req_slot_latched +: 8] = req_len_latched;
            arb_req_counter[64*req_slot_latched +: 64] = req_counter_latched;
            arb_req_data[512*req_slot_latched +: 512] = req_data_latched;
            arb_req_tag[128*req_slot_latched +: 128] = req_tag_latched;
        end

        arb_rsp_ready = 4'd0;
        if (req_inflight)
            arb_rsp_ready[req_slot_latched] = 1'b1;
    end

    aead_arbiter_4session u_arbiter (
        .clk_i(s_axi_aclk), .rst_ni(s_axi_aresetn),
        .cfg_write_i(cfg_pending), .cfg_slot_i(cfg_slot_latched),
        .cfg_valid_i(cfg_valid_latched),
        .cfg_session_id_i(cfg_session_id_latched),
        .cfg_tx_key_i(cfg_tx_key_latched), .cfg_rx_key_i(cfg_rx_key_latched),
        .cfg_tx_nonce_prefix_i(cfg_tx_prefix_latched),
        .cfg_rx_nonce_prefix_i(cfg_rx_prefix_latched),
        .cfg_ready_o(arb_cfg_ready),
        .req_valid_i(arb_req_valid), .req_ready_o(arb_req_ready),
        .req_decrypt_i(arb_req_decrypt), .req_data_len_i(arb_req_data_len),
        .req_counter_i(arb_req_counter), .req_data_i(arb_req_data),
        .req_tag_i(arb_req_tag), .rsp_valid_o(arb_rsp_valid),
        .rsp_ready_i(arb_rsp_ready), .rsp_auth_ok_o(arb_rsp_auth),
        .rsp_error_o(arb_rsp_error), .rsp_counter_o(arb_rsp_counter),
        .rsp_data_o(arb_rsp_data), .rsp_tag_o(arb_rsp_tag)
    );

    mlkem_session_kdf u_session_kdf (
        .clk_i(s_axi_aclk),.rst_ni(s_axi_aresetn),.start_i(kdf_start),
        .shared_secret_i(kdf_shared_secret),.transcript_hash_i(kdf_transcript_hash),
        .busy_o(kdf_busy),.done_o(kdf_done),.pc_to_zb_key_o(kdf_pc_key),
        .pc_to_zb_prefix_o(kdf_pc_prefix),.zb_to_pc_key_o(kdf_zb_key),
        .zb_to_pc_prefix_o(kdf_zb_prefix));

    always_ff @(posedge s_axi_aclk) begin
        if (!s_axi_aresetn) begin
            request_slot_reg <= '0;
            data_len_reg <= '0;
            counter_reg <= '0;
            cfg_session_id_reg <= '0;
            tx_prefix_reg <= '0;
            rx_prefix_reg <= '0;
            req_issue_pending <= 1'b0;
            req_inflight <= 1'b0;
            req_decrypt_latched <= 1'b0;
            req_slot_latched <= '0;
            req_len_latched <= '0;
            req_counter_latched <= '0;
            req_data_latched <= '0;
            req_tag_latched <= '0;
            response_done <= 1'b0;
            response_auth <= 1'b0;
            response_error <= 1'b0;
            response_counter <= '0;
            response_data <= '0;
            response_tag <= '0;
            cfg_pending <= 1'b0;
            cfg_slot_latched <= '0;
            cfg_valid_latched <= 1'b0;
            cfg_session_id_latched <= '0;
            cfg_tx_key_latched <= '0;
            cfg_rx_key_latched <= '0;
            cfg_tx_prefix_latched <= '0;
            cfg_rx_prefix_latched <= '0;
            kdf_start <= 1'b0;
            kdf_shared_secret <= '0;
            kdf_transcript_hash <= '0;
            for (i_seq=0; i_seq<8; i_seq=i_seq+1) begin
                tx_key_words[i_seq] <= '0;
                rx_key_words[i_seq] <= '0;
                shared_secret_words[i_seq] <= '0;
                transcript_hash_words[i_seq] <= '0;
            end
            for (i_seq=0; i_seq<16; i_seq=i_seq+1)
                input_data_words[i_seq] <= '0;
            for (i_seq=0; i_seq<4; i_seq=i_seq+1)
                input_tag_words[i_seq] <= '0;
        end else begin
            kdf_start <= 1'b0;
            if (cfg_pending && arb_cfg_ready)
                cfg_pending <= 1'b0;

            /* ZedBoard role: TX is ZB->PC and RX is PC->ZB. */
            if (kdf_done) begin
                cfg_slot_latched <= request_slot_reg;
                cfg_valid_latched <= 1'b1;
                cfg_session_id_latched <= cfg_session_id_reg;
                cfg_tx_key_latched <= kdf_zb_key;
                cfg_rx_key_latched <= kdf_pc_key;
                cfg_tx_prefix_latched <= kdf_zb_prefix;
                cfg_rx_prefix_latched <= kdf_pc_prefix;
                cfg_pending <= 1'b1;
            end

            if (req_issue_pending && arb_req_ready[req_slot_latched])
                req_issue_pending <= 1'b0;

            if (req_inflight && arb_rsp_valid[req_slot_latched]
                && arb_rsp_ready[req_slot_latched]) begin
                response_counter <= arb_rsp_counter[64*req_slot_latched +: 64];
                response_data <= arb_rsp_data[512*req_slot_latched +: 512];
                response_tag <= arb_rsp_tag[128*req_slot_latched +: 128];
                response_auth <= arb_rsp_auth[req_slot_latched];
                response_error <= arb_rsp_error[req_slot_latched];
                response_done <= 1'b1;
                req_inflight <= 1'b0;
            end

            if (write_commit) begin
                case (awaddr_held[9:0])
                    REG_CONTROL: begin
                        if (wstrb_held[1] && wdata_held[8])
                            response_done <= 1'b0;
                        if (wstrb_held[0] && wdata_held[0]
                            && !req_inflight && !req_issue_pending) begin
                            req_decrypt_latched <= wdata_held[1];
                            req_slot_latched <= request_slot_reg;
                            req_len_latched <= data_len_reg;
                            req_counter_latched <= counter_reg;
                            for (i_seq=0; i_seq<16; i_seq=i_seq+1)
                                req_data_latched[32*i_seq +: 32] <= input_data_words[i_seq];
                            for (i_seq=0; i_seq<4; i_seq=i_seq+1)
                                req_tag_latched[32*i_seq +: 32] <= input_tag_words[i_seq];
                            req_issue_pending <= 1'b1;
                            req_inflight <= 1'b1;
                            response_done <= 1'b0;
                            response_auth <= 1'b0;
                            response_error <= 1'b0;
                        end
                    end
                    REG_REQUEST_SLOT:
                        request_slot_reg <= merge_wstrb(
                            {30'd0,request_slot_reg}, wdata_held,wstrb_held);
                    REG_DATA_LEN:
                        data_len_reg <= merge_wstrb(
                            {24'd0,data_len_reg}, wdata_held,wstrb_held);
                    REG_COUNTER_LO:
                        counter_reg[31:0] <= merge_wstrb(
                            counter_reg[31:0], wdata_held,wstrb_held);
                    REG_COUNTER_HI:
                        counter_reg[63:32] <= merge_wstrb(
                            counter_reg[63:32], wdata_held,wstrb_held);
                    REG_CFG_SESSION_ID:
                        cfg_session_id_reg <= merge_wstrb(
                            cfg_session_id_reg,wdata_held,wstrb_held);
                    REG_CFG_CONTROL: begin
                        if (wstrb_held[3] && wdata_held[31] && !cfg_pending) begin
                            cfg_slot_latched <= wdata_held[1:0];
                            cfg_valid_latched <= wdata_held[8];
                            cfg_session_id_latched <= cfg_session_id_reg;
                            for (i_seq=0; i_seq<8; i_seq=i_seq+1) begin
                                cfg_tx_key_latched[32*i_seq +: 32] <= tx_key_words[i_seq];
                                cfg_rx_key_latched[32*i_seq +: 32] <= rx_key_words[i_seq];
                            end
                            cfg_tx_prefix_latched <= tx_prefix_reg;
                            cfg_rx_prefix_latched <= rx_prefix_reg;
                            cfg_pending <= 1'b1;
                        end
                    end
                    REG_KDF_CONTROL: begin
                        if (wstrb_held[0] && wdata_held[0] && !kdf_busy
                            && !cfg_pending) begin
                            for (i_seq=0; i_seq<8; i_seq=i_seq+1) begin
                                kdf_shared_secret[32*i_seq+:32] <= shared_secret_words[i_seq];
                                kdf_transcript_hash[32*i_seq+:32] <= transcript_hash_words[i_seq];
                            end
                            kdf_start <= 1'b1;
                        end
                    end
                    REG_TX_PREFIX:
                        tx_prefix_reg <= merge_wstrb(tx_prefix_reg,wdata_held,wstrb_held);
                    REG_RX_PREFIX:
                        rx_prefix_reg <= merge_wstrb(rx_prefix_reg,wdata_held,wstrb_held);
                    default: begin
                        for (i_seq=0; i_seq<8; i_seq=i_seq+1) begin
                            if (awaddr_held[9:0] == REG_TX_KEY_BASE + 4*i_seq)
                                tx_key_words[i_seq] <= merge_wstrb(
                                    tx_key_words[i_seq],wdata_held,wstrb_held);
                            if (awaddr_held[9:0] == REG_RX_KEY_BASE + 4*i_seq)
                                rx_key_words[i_seq] <= merge_wstrb(
                                    rx_key_words[i_seq],wdata_held,wstrb_held);
                            if (awaddr_held[9:0] == REG_SHARED_SECRET + 4*i_seq)
                                shared_secret_words[i_seq] <= merge_wstrb(
                                    shared_secret_words[i_seq],wdata_held,wstrb_held);
                            if (awaddr_held[9:0] == REG_TRANSCRIPT_HASH + 4*i_seq)
                                transcript_hash_words[i_seq] <= merge_wstrb(
                                    transcript_hash_words[i_seq],wdata_held,wstrb_held);
                        end
                        for (i_seq=0; i_seq<16; i_seq=i_seq+1)
                            if (awaddr_held[9:0] == REG_INPUT_DATA_BASE + 4*i_seq)
                                input_data_words[i_seq] <= merge_wstrb(
                                    input_data_words[i_seq],wdata_held,wstrb_held);
                        for (i_seq=0; i_seq<4; i_seq=i_seq+1)
                            if (awaddr_held[9:0] == REG_INPUT_TAG_BASE + 4*i_seq)
                                input_tag_words[i_seq] <= merge_wstrb(
                                    input_tag_words[i_seq],wdata_held,wstrb_held);
                    end
                endcase
            end
        end
    end

endmodule
