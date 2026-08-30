`timescale 1ns/1ps

/* Connects the ML-KEM result/KDF path to the four-session AEAD engine. */
module secure_channel_core (
    input logic clk_i,input logic rst_ni,
    input logic handshake_start_i,input logic [1:0] handshake_slot_i,
    input logic [31:0] handshake_session_id_i,
    input logic [255:0] handshake_shared_secret_i,
    input logic [255:0] handshake_transcript_hash_i,
    output logic handshake_busy_o,output logic handshake_done_o,
    input logic [3:0] req_valid_i,output logic [3:0] req_ready_o,
    input logic [3:0] req_decrypt_i,input logic [31:0] req_data_len_i,
    input logic [255:0] req_counter_i,input logic [2047:0] req_data_i,
    input logic [511:0] req_tag_i,output logic [3:0] rsp_valid_o,
    input logic [3:0] rsp_ready_i,output logic [3:0] rsp_auth_ok_o,
    output logic [3:0] rsp_error_o,output logic [255:0] rsp_counter_o,
    output logic [2047:0] rsp_data_o,output logic [511:0] rsp_tag_o
);
    logic kdf_done,cfg_pending,cfg_ready;
    logic [1:0] slot_reg; logic [31:0] session_reg;
    logic [255:0] pc_key,zb_key;logic [31:0] pc_prefix,zb_prefix;

    mlkem_session_kdf u_kdf(.clk_i(clk_i),.rst_ni(rst_ni),
        .start_i(handshake_start_i),.shared_secret_i(handshake_shared_secret_i),
        .transcript_hash_i(handshake_transcript_hash_i),.busy_o(handshake_busy_o),
        .done_o(kdf_done),.pc_to_zb_key_o(pc_key),.pc_to_zb_prefix_o(pc_prefix),
        .zb_to_pc_key_o(zb_key),.zb_to_pc_prefix_o(zb_prefix));

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if(!rst_ni) begin slot_reg<=0;session_reg<=0;cfg_pending<=0;handshake_done_o<=0;end
        else begin
            handshake_done_o<=0;
            if(handshake_start_i)begin slot_reg<=handshake_slot_i;session_reg<=handshake_session_id_i;end
            if(kdf_done)cfg_pending<=1;
            if(cfg_pending&&cfg_ready)begin cfg_pending<=0;handshake_done_o<=1;end
        end
    end

    aead_arbiter_4session u_arbiter(.clk_i(clk_i),.rst_ni(rst_ni),
        .cfg_write_i(cfg_pending),.cfg_slot_i(slot_reg),.cfg_valid_i(1'b1),
        .cfg_session_id_i(session_reg),.cfg_tx_key_i(zb_key),.cfg_rx_key_i(pc_key),
        .cfg_tx_nonce_prefix_i(zb_prefix),.cfg_rx_nonce_prefix_i(pc_prefix),
        .cfg_ready_o(cfg_ready),.req_valid_i(req_valid_i),.req_ready_o(req_ready_o),
        .req_decrypt_i(req_decrypt_i),.req_data_len_i(req_data_len_i),
        .req_counter_i(req_counter_i),.req_data_i(req_data_i),.req_tag_i(req_tag_i),
        .rsp_valid_o(rsp_valid_o),.rsp_ready_i(rsp_ready_i),
        .rsp_auth_ok_o(rsp_auth_ok_o),.rsp_error_o(rsp_error_o),
        .rsp_counter_o(rsp_counter_o),.rsp_data_o(rsp_data_o),.rsp_tag_o(rsp_tag_o));
endmodule
