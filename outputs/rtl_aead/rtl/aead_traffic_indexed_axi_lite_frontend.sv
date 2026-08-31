`timescale 1ns/1ps

/* AXI4-Lite adapter for one PS-scheduled request with an indexed slot. */
module aead_traffic_indexed_axi_lite_frontend #(
    parameter integer C_S_AXI_ADDR_WIDTH = 9,
    parameter integer NUM_SESSIONS = 64,
    parameter integer SLOT_WIDTH = $clog2(NUM_SESSIONS)
)(
    input logic clk_i,
    input logic rst_ni,
    input logic [C_S_AXI_ADDR_WIDTH-1:0] s_axi_awaddr,
    input logic s_axi_awvalid,
    output logic s_axi_awready,
    input logic [31:0] s_axi_wdata,
    input logic [3:0] s_axi_wstrb,
    input logic s_axi_wvalid,
    output logic s_axi_wready,
    output logic [1:0] s_axi_bresp,
    output logic s_axi_bvalid,
    input logic s_axi_bready,
    input logic [C_S_AXI_ADDR_WIDTH-1:0] s_axi_araddr,
    input logic s_axi_arvalid,
    output logic s_axi_arready,
    output logic [31:0] s_axi_rdata,
    output logic [1:0] s_axi_rresp,
    output logic s_axi_rvalid,
    input logic s_axi_rready,

    input logic fault_detected_i,
    input logic [7:0] fault_code_i,

    output logic req_valid_o,
    input logic req_ready_i,
    output logic [SLOT_WIDTH-1:0] req_slot_o,
    output logic req_decrypt_o,
    output logic [7:0] req_data_len_o,
    output logic [63:0] req_counter_o,
    output logic [511:0] req_data_o,
    output logic [127:0] req_tag_o,
    input logic rsp_valid_i,
    output logic rsp_ready_o,
    input logic rsp_auth_ok_i,
    input logic rsp_error_i,
    input logic [SLOT_WIDTH-1:0] rsp_slot_i,
    input logic [63:0] rsp_counter_i,
    input logic [511:0] rsp_data_i,
    input logic [127:0] rsp_tag_i
);
    localparam [8:0] REG_VERSION         = 9'h000;
    localparam [8:0] REG_CONTROL         = 9'h004;
    localparam [8:0] REG_STATUS          = 9'h008;
    localparam [8:0] REG_SLOT            = 9'h00c;
    localparam [8:0] REG_LENGTH          = 9'h010;
    localparam [8:0] REG_COUNTER_LO      = 9'h014;
    localparam [8:0] REG_COUNTER_HI      = 9'h018;
    localparam [8:0] REG_RSP_COUNTER_LO  = 9'h01c;
    localparam [8:0] REG_RSP_COUNTER_HI  = 9'h020;
    localparam [8:0] REG_FAULT           = 9'h024;
    localparam [8:0] REG_RSP_SLOT        = 9'h028;
    localparam [8:0] REG_INPUT_DATA      = 9'h100;
    localparam [8:0] REG_INPUT_TAG       = 9'h140;
    localparam [8:0] REG_OUTPUT_DATA     = 9'h180;
    localparam [8:0] REG_OUTPUT_TAG      = 9'h1c0;
    localparam [7:0] NUM_SESSIONS_U8     = NUM_SESSIONS;
    localparam [7:0] SLOT_WIDTH_U8       = SLOT_WIDTH;

    logic aw_hold, w_hold, write_commit;
    logic [C_S_AXI_ADDR_WIDTH-1:0] awaddr_q;
    logic [31:0] wdata_q;
    logic [3:0] wstrb_q;
    logic [SLOT_WIDTH-1:0] slot_reg, slot_q, rsp_slot_q;
    logic [7:0] length_reg, length_q;
    logic [63:0] counter_reg, counter_q, rsp_counter_q;
    logic decrypt_q, pending, inflight, done_q, auth_q, error_q;
    logic [511:0] data_q, rsp_data_q;
    logic [127:0] tag_q, rsp_tag_q;
    logic [31:0] input_data [0:15];
    logic [31:0] input_tag [0:3];
    logic [31:0] read_mux;
    integer i;

    function automatic [31:0] merge_wstrb(
        input [31:0] old_value,
        input [31:0] new_value,
        input [3:0] strobe);
        integer b;
        begin
            merge_wstrb = old_value;
            for (b = 0; b < 4; b = b + 1)
                if (strobe[b])
                    merge_wstrb[8*b +: 8] = new_value[8*b +: 8];
        end
    endfunction

    assign s_axi_awready = !aw_hold && !s_axi_bvalid;
    assign s_axi_wready  = !w_hold && !s_axi_bvalid;
    assign s_axi_bresp   = 2'b00;
    assign s_axi_arready = !s_axi_rvalid;
    assign s_axi_rresp   = 2'b00;

    assign req_valid_o    = pending;
    assign req_slot_o     = slot_q;
    assign req_decrypt_o  = decrypt_q;
    assign req_data_len_o = length_q;
    assign req_counter_o  = counter_q;
    assign req_data_o     = data_q;
    assign req_tag_o      = tag_q;
    assign rsp_ready_o    = inflight;

    always_comb begin
        read_mux = 32'd0;
        case (s_axi_araddr[8:0])
            REG_VERSION: read_mux = {16'h0004, NUM_SESSIONS_U8, SLOT_WIDTH_U8};
            REG_STATUS: begin
                read_mux[0] = inflight;
                read_mux[1] = done_q;
                read_mux[2] = auth_q;
                read_mux[3] = error_q;
                read_mux[4] = 1'b0;
                read_mux[5] = pending;
                read_mux[6] = fault_detected_i;
            end
            REG_SLOT: read_mux = {{(32-SLOT_WIDTH){1'b0}}, slot_reg};
            REG_LENGTH: read_mux = {24'd0, length_reg};
            REG_COUNTER_LO: read_mux = counter_reg[31:0];
            REG_COUNTER_HI: read_mux = counter_reg[63:32];
            REG_RSP_COUNTER_LO: read_mux = rsp_counter_q[31:0];
            REG_RSP_COUNTER_HI: read_mux = rsp_counter_q[63:32];
            REG_FAULT: read_mux = {23'd0, fault_detected_i, fault_code_i};
            REG_RSP_SLOT: read_mux = {{(32-SLOT_WIDTH){1'b0}}, rsp_slot_q};
            default: begin
                for (int rd = 0; rd < 16; rd++) begin
                    if (s_axi_araddr[8:0] == REG_INPUT_DATA + 4*rd)
                        read_mux = input_data[rd];
                    if (s_axi_araddr[8:0] == REG_OUTPUT_DATA + 4*rd)
                        read_mux = rsp_data_q[32*rd +: 32];
                end
                for (int rt = 0; rt < 4; rt++) begin
                    if (s_axi_araddr[8:0] == REG_INPUT_TAG + 4*rt)
                        read_mux = input_tag[rt];
                    if (s_axi_araddr[8:0] == REG_OUTPUT_TAG + 4*rt)
                        read_mux = rsp_tag_q[32*rt +: 32];
                end
            end
        endcase
    end

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            aw_hold          <= 1'b0;
            w_hold           <= 1'b0;
            write_commit     <= 1'b0;
            s_axi_bvalid     <= 1'b0;
            s_axi_rvalid     <= 1'b0;
            s_axi_rdata      <= 32'd0;
            slot_reg         <= '0;
            slot_q           <= '0;
            rsp_slot_q       <= '0;
            length_reg       <= '0;
            length_q         <= '0;
            counter_reg      <= '0;
            counter_q        <= '0;
            decrypt_q        <= 1'b0;
            pending          <= 1'b0;
            inflight         <= 1'b0;
            done_q           <= 1'b0;
            auth_q           <= 1'b0;
            error_q          <= 1'b0;
            data_q           <= '0;
            tag_q            <= '0;
            rsp_counter_q    <= '0;
            rsp_data_q       <= '0;
            rsp_tag_q        <= '0;
            for (i = 0; i < 16; i = i + 1)
                input_data[i] <= 32'd0;
            for (i = 0; i < 4; i = i + 1)
                input_tag[i] <= 32'd0;
        end else begin
            write_commit <= 1'b0;

            if (s_axi_awvalid && s_axi_awready) begin
                awaddr_q <= s_axi_awaddr;
                aw_hold  <= 1'b1;
            end
            if (s_axi_wvalid && s_axi_wready) begin
                wdata_q <= s_axi_wdata;
                wstrb_q <= s_axi_wstrb;
                w_hold  <= 1'b1;
            end
            if (aw_hold && w_hold && !s_axi_bvalid) begin
                write_commit <= 1'b1;
                aw_hold      <= 1'b0;
                w_hold       <= 1'b0;
                s_axi_bvalid <= 1'b1;
            end else if (s_axi_bvalid && s_axi_bready) begin
                s_axi_bvalid <= 1'b0;
            end

            if (s_axi_arvalid && s_axi_arready) begin
                s_axi_rdata  <= read_mux;
                s_axi_rvalid <= 1'b1;
            end else if (s_axi_rvalid && s_axi_rready) begin
                s_axi_rvalid <= 1'b0;
            end

            if (pending && req_ready_i)
                pending <= 1'b0;

            if (inflight && rsp_valid_i && rsp_ready_o) begin
                rsp_slot_q    <= rsp_slot_i;
                rsp_counter_q <= rsp_counter_i;
                rsp_data_q    <= rsp_data_i;
                rsp_tag_q     <= rsp_tag_i;
                auth_q        <= rsp_auth_ok_i;
                error_q       <= rsp_error_i;
                done_q        <= 1'b1;
                inflight      <= 1'b0;
            end

            if (write_commit) begin
                case (awaddr_q[8:0])
                    REG_CONTROL: begin
                        if (wstrb_q[1] && wdata_q[8])
                            done_q <= 1'b0;
                        if (wstrb_q[0] && wdata_q[0] && !pending && !inflight) begin
                            slot_q      <= slot_reg;
                            length_q    <= length_reg;
                            counter_q   <= counter_reg;
                            decrypt_q   <= wdata_q[1];
                            for (i = 0; i < 16; i = i + 1)
                                data_q[32*i +: 32] <= input_data[i];
                            for (i = 0; i < 4; i = i + 1)
                                tag_q[32*i +: 32] <= input_tag[i];
                            pending  <= 1'b1;
                            inflight <= 1'b1;
                            done_q   <= 1'b0;
                            auth_q   <= 1'b0;
                            error_q  <= 1'b0;
                        end
                    end
                    REG_SLOT: slot_reg <= merge_wstrb(
                        {{(32-SLOT_WIDTH){1'b0}}, slot_reg}, wdata_q, wstrb_q);
                    REG_LENGTH: length_reg <= merge_wstrb(
                        {24'd0, length_reg}, wdata_q, wstrb_q);
                    REG_COUNTER_LO: counter_reg[31:0] <= merge_wstrb(
                        counter_reg[31:0], wdata_q, wstrb_q);
                    REG_COUNTER_HI: counter_reg[63:32] <= merge_wstrb(
                        counter_reg[63:32], wdata_q, wstrb_q);
                    default: begin
                        for (i = 0; i < 16; i = i + 1)
                            if (awaddr_q[8:0] == REG_INPUT_DATA + 4*i)
                                input_data[i] <= merge_wstrb(input_data[i], wdata_q, wstrb_q);
                        for (i = 0; i < 4; i = i + 1)
                            if (awaddr_q[8:0] == REG_INPUT_TAG + 4*i)
                                input_tag[i] <= merge_wstrb(input_tag[i], wdata_q, wstrb_q);
                    end
                endcase
            end
        end
    end
endmodule
