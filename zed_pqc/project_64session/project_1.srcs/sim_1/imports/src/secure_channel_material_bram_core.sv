`timescale 1ns/1ps

/* Installs ML-KEM-derived traffic material into the indexed BRAM table. */
module secure_channel_material_bram_core #(
    parameter integer NUM_SESSIONS = 64,
    parameter integer SLOT_WIDTH = $clog2(NUM_SESSIONS)
)(
    input logic clk_i,
    input logic rst_ni,
    input logic install_i,
    input logic [SLOT_WIDTH-1:0] slot_i,
    input logic [31:0] session_id_i,
    input logic [575:0] material_i,
    output logic install_busy_o,
    output logic install_done_o,

    input logic req_valid_i,
    output logic req_ready_o,
    input logic [SLOT_WIDTH-1:0] req_slot_i,
    input logic req_decrypt_i,
    input logic [7:0] req_data_len_i,
    input logic [63:0] req_counter_i,
    input logic [511:0] req_data_i,
    input logic [127:0] req_tag_i,
    output logic rsp_valid_o,
    input logic rsp_ready_i,
    output logic rsp_auth_ok_o,
    output logic rsp_error_o,
    output logic [SLOT_WIDTH-1:0] rsp_slot_o,
    output logic [63:0] rsp_counter_o,
    output logic [511:0] rsp_data_o,
    output logic [127:0] rsp_tag_o
);
    logic pending, accepted;
    logic cfg_ready, cfg_done;
    logic [SLOT_WIDTH-1:0] slot_q;
    logic [31:0] session_q;
    logic [575:0] material_q;

    assign install_busy_o = pending || accepted;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            pending        <= 1'b0;
            accepted       <= 1'b0;
            install_done_o <= 1'b0;
            slot_q          <= '0;
            session_q       <= '0;
            material_q      <= '0;
        end else begin
            install_done_o <= 1'b0;

            if (install_i && !pending && !accepted) begin
                pending   <= 1'b1;
                slot_q    <= slot_i;
                session_q <= session_id_i;
                material_q <= material_i;
            end

            if (pending && cfg_ready) begin
                pending  <= 1'b0;
                accepted <= 1'b1;
            end

            if (accepted && cfg_done) begin
                accepted       <= 1'b0;
                install_done_o <= 1'b1;
            end
        end
    end

    aead_session_manager_bram #(
        .NUM_SESSIONS(NUM_SESSIONS),
        .SLOT_WIDTH(SLOT_WIDTH)
    ) u_sessions (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .cfg_write_i(pending),
        .cfg_slot_i(slot_q),
        .cfg_valid_i(1'b1),
        .cfg_session_id_i(session_q),
        .cfg_tx_key_i(material_q[543:288]),
        .cfg_rx_key_i(material_q[255:0]),
        .cfg_tx_nonce_prefix_i(material_q[575:544]),
        .cfg_rx_nonce_prefix_i(material_q[287:256]),
        .cfg_ready_o(cfg_ready),
        .cfg_done_o(cfg_done),
        .req_valid_i(req_valid_i),
        .req_ready_o(req_ready_o),
        .req_slot_i(req_slot_i),
        .req_decrypt_i(req_decrypt_i),
        .req_data_len_i(req_data_len_i),
        .req_counter_i(req_counter_i),
        .req_data_i(req_data_i),
        .req_tag_i(req_tag_i),
        .rsp_valid_o(rsp_valid_o),
        .rsp_ready_i(rsp_ready_i),
        .rsp_auth_ok_o(rsp_auth_ok_o),
        .rsp_error_o(rsp_error_o),
        .rsp_slot_o(rsp_slot_o),
        .rsp_counter_o(rsp_counter_o),
        .rsp_data_o(rsp_data_o),
        .rsp_tag_o(rsp_tag_o)
    );
endmodule

