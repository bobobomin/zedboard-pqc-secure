`timescale 1ns/1ps

/* Final PS-facing top: one AXI-Lite port loads/runs ML-KEM and a second
 * AXI-Lite port moves fixed-size AEAD packets through the same session table. */
module mlkem_secure_channel_complete_axi_top #(
  parameter integer MAX_STAGE_CYCLES=300000)(
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
  logic[3:0]qv,qr,qd,sv,sready,sauth,serr;logic[31:0]qlen;
  logic[255:0]qcount,scount;logic[2047:0]qdata,sdata;logic[511:0]qtag,stag;
  /* Single reset synchroniser for this clock domain: the board reset asserts
     asynchronously and releases on a clock edge, so every block below starts
     on the same edge. */
  (* ASYNC_REG="TRUE" *) logic[1:0]rst_sync_q;logic rst_sync_n;
  always_ff @(posedge aclk or negedge aresetn)
    if(!aresetn)rst_sync_q<=2'b00;else rst_sync_q<={rst_sync_q[0],1'b1};
  assign rst_sync_n=rst_sync_q[1];
  mlkem_secure_channel_fault_protected_axi_top #(.MAX_STAGE_CYCLES(MAX_STAGE_CYCLES)) core(
    aclk,rst_sync_n,m_awaddr,m_awvalid,m_awready,m_wdata,m_wstrb,m_wvalid,m_wready,m_bresp,m_bvalid,m_bready,
    m_araddr,m_arvalid,m_arready,m_rdata,m_rresp,m_rvalid,m_rready,fault_inject_i,
    fault_detected_o,fault_code_o,qv,qr,qd,qlen,qcount,qdata,qtag,sv,sready,sauth,serr,scount,sdata,stag);
  aead_traffic_axi_lite_frontend traffic(aclk,rst_sync_n,a_awaddr,a_awvalid,a_awready,
    a_wdata,a_wstrb,a_wvalid,a_wready,a_bresp,a_bvalid,a_bready,a_araddr,a_arvalid,a_arready,
    a_rdata,a_rresp,a_rvalid,a_rready,fault_detected_o,fault_code_o,qv,qr,qd,qlen,qcount,
    qdata,qtag,sv,sready,sauth,serr,scount,sdata,stag);
endmodule
