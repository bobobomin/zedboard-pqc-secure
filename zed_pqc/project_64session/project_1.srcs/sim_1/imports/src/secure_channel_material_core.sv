`timescale 1ns/1ps

/* Installs already-derived 72-byte traffic material into the four-session AEAD core. */
module secure_channel_material_core(
    input logic clk_i,input logic rst_ni,input logic install_i,input logic[1:0]slot_i,
    input logic[31:0]session_id_i,input logic[575:0]material_i,
    output logic install_busy_o,output logic install_done_o,
    input logic[3:0]req_valid_i,output logic[3:0]req_ready_o,
    input logic[3:0]req_decrypt_i,input logic[31:0]req_data_len_i,
    input logic[255:0]req_counter_i,input logic[2047:0]req_data_i,input logic[511:0]req_tag_i,
    output logic[3:0]rsp_valid_o,input logic[3:0]rsp_ready_i,output logic[3:0]rsp_auth_ok_o,
    output logic[3:0]rsp_error_o,output logic[255:0]rsp_counter_o,
    output logic[2047:0]rsp_data_o,output logic[511:0]rsp_tag_o);
    logic pending,cfg_ready;logic[1:0]slot_q;logic[31:0]session_q;logic[575:0]material_q;
    assign install_busy_o=pending;
    always_ff @(posedge clk_i or negedge rst_ni)begin
      if(!rst_ni)begin pending<=0;install_done_o<=0;slot_q<=0;session_q<=0;material_q<=0;end
      else begin install_done_o<=0;
        if(install_i)begin pending<=1;slot_q<=slot_i;session_q<=session_id_i;material_q<=material_i;end
        if(pending&&cfg_ready)begin pending<=0;install_done_o<=1;end
      end
    end
    aead_arbiter_4session arb(.clk_i(clk_i),.rst_ni(rst_ni),
      .cfg_write_i(pending),.cfg_slot_i(slot_q),.cfg_valid_i(1'b1),.cfg_session_id_i(session_q),
      .cfg_tx_key_i(material_q[543:288]),.cfg_rx_key_i(material_q[255:0]),
      .cfg_tx_nonce_prefix_i(material_q[575:544]),.cfg_rx_nonce_prefix_i(material_q[287:256]),
      .cfg_ready_o(cfg_ready),.req_valid_i(req_valid_i),.req_ready_o(req_ready_o),
      .req_decrypt_i(req_decrypt_i),.req_data_len_i(req_data_len_i),.req_counter_i(req_counter_i),
      .req_data_i(req_data_i),.req_tag_i(req_tag_i),.rsp_valid_o(rsp_valid_o),
      .rsp_ready_i(rsp_ready_i),.rsp_auth_ok_o(rsp_auth_ok_o),.rsp_error_o(rsp_error_o),
      .rsp_counter_o(rsp_counter_o),.rsp_data_o(rsp_data_o),.rsp_tag_o(rsp_tag_o));
endmodule
