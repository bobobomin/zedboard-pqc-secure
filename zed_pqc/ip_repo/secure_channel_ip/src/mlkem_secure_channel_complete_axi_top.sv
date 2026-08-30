`timescale 1ns/1ps

/* Final PS-facing top: one AXI-Lite port loads/runs ML-KEM and a second
 * AXI-Lite port moves fixed-size AEAD packets through the same session table. */
module mlkem_secure_channel_complete_axi_top #(
  parameter integer MAX_STAGE_CYCLES=300000,
  parameter integer NUM_SESSIONS=64,
  parameter integer SLOT_WIDTH=$clog2(NUM_SESSIONS))(
  input logic aclk,input logic aresetn,
  input logic[7:0]m_awaddr,input logic m_awvalid,output logic m_awready,
  input logic[31:0]m_wdata,input logic[3:0]m_wstrb,input logic m_wvalid,output logic m_wready,
  output logic[1:0]m_bresp,output logic m_bvalid,input logic m_bready,
  input logic[7:0]m_araddr,input logic m_arvalid,output logic m_arready,
  output logic[31:0]m_rdata,output logic[1:0]m_rresp,output logic m_rvalid,input logic m_rready,
  input logic[8:0]a_awaddr,input logic a_awvalid,output logic a_awready,
  input logic[31:0]a_wdata,input logic[3:0]a_wstrb,input logic a_wvalid,output logic a_wready,
  output logic[1:0]a_bresp,output logic a_bvalid,input logic a_bready,
  input logic[8:0]a_araddr,input logic a_arvalid,output logic a_arready,
  output logic[31:0]a_rdata,output logic[1:0]a_rresp,output logic a_rvalid,input logic a_rready,
  input logic[5:0]fault_inject_i,output logic fault_detected_o,output logic[7:0]fault_code_o);
  logic req_valid,req_ready,req_decrypt;
  logic[SLOT_WIDTH-1:0]req_slot,rsp_slot;
  logic[7:0]req_len;
  logic[63:0]req_counter,rsp_counter;
  logic[511:0]req_data,rsp_data;
  logic[127:0]req_tag,rsp_tag;
  logic rsp_valid,rsp_ready,rsp_auth,rsp_error;
  (* ASYNC_REG="TRUE" *) logic[1:0]rst_sync_q;
  logic rst_sync_n;

  always_ff @(posedge aclk or negedge aresetn)
    if(!aresetn) rst_sync_q<=2'b00;
    else         rst_sync_q<={rst_sync_q[0],1'b1};

  assign rst_sync_n=rst_sync_q[1];

  mlkem_secure_channel_fault_protected_indexed_axi_top #(
    .MAX_STAGE_CYCLES(MAX_STAGE_CYCLES),.NUM_SESSIONS(NUM_SESSIONS),.SLOT_WIDTH(SLOT_WIDTH)) core(
    .s_axi_aclk(aclk),.s_axi_aresetn(rst_sync_n),.s_axi_awaddr(m_awaddr),
    .s_axi_awvalid(m_awvalid),.s_axi_awready(m_awready),.s_axi_wdata(m_wdata),
    .s_axi_wstrb(m_wstrb),.s_axi_wvalid(m_wvalid),.s_axi_wready(m_wready),
    .s_axi_bresp(m_bresp),.s_axi_bvalid(m_bvalid),.s_axi_bready(m_bready),
    .s_axi_araddr(m_araddr),.s_axi_arvalid(m_arvalid),.s_axi_arready(m_arready),
    .s_axi_rdata(m_rdata),.s_axi_rresp(m_rresp),.s_axi_rvalid(m_rvalid),.s_axi_rready(m_rready),
    .fault_inject_i(fault_inject_i),.fault_detected_o(fault_detected_o),.fault_code_o(fault_code_o),
    .req_valid_i(req_valid),.req_ready_o(req_ready),.req_slot_i(req_slot),
    .req_decrypt_i(req_decrypt),.req_data_len_i(req_len),.req_counter_i(req_counter),
    .req_data_i(req_data),.req_tag_i(req_tag),.rsp_valid_o(rsp_valid),
    .rsp_ready_i(rsp_ready),.rsp_auth_ok_o(rsp_auth),.rsp_error_o(rsp_error),
    .rsp_slot_o(rsp_slot),.rsp_counter_o(rsp_counter),.rsp_data_o(rsp_data),.rsp_tag_o(rsp_tag));

  aead_traffic_indexed_axi_lite_frontend #(
    .NUM_SESSIONS(NUM_SESSIONS),.SLOT_WIDTH(SLOT_WIDTH)) traffic(
    .clk_i(aclk),.rst_ni(rst_sync_n),.s_axi_awaddr(a_awaddr),.s_axi_awvalid(a_awvalid),
    .s_axi_awready(a_awready),.s_axi_wdata(a_wdata),.s_axi_wstrb(a_wstrb),
    .s_axi_wvalid(a_wvalid),.s_axi_wready(a_wready),.s_axi_bresp(a_bresp),
    .s_axi_bvalid(a_bvalid),.s_axi_bready(a_bready),.s_axi_araddr(a_araddr),
    .s_axi_arvalid(a_arvalid),.s_axi_arready(a_arready),.s_axi_rdata(a_rdata),
    .s_axi_rresp(a_rresp),.s_axi_rvalid(a_rvalid),.s_axi_rready(a_rready),
    .fault_detected_i(fault_detected_o),.fault_code_i(fault_code_o),
    .req_valid_o(req_valid),.req_ready_i(req_ready),.req_slot_o(req_slot),
    .req_decrypt_o(req_decrypt),.req_data_len_o(req_len),.req_counter_o(req_counter),
    .req_data_o(req_data),.req_tag_o(req_tag),.rsp_valid_i(rsp_valid),
    .rsp_ready_o(rsp_ready),.rsp_auth_ok_i(rsp_auth),.rsp_error_i(rsp_error),
    .rsp_slot_i(rsp_slot),.rsp_counter_i(rsp_counter),.rsp_data_i(rsp_data),.rsp_tag_i(rsp_tag));
endmodule
