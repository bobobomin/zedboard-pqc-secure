`timescale 1ns/1ps

/* Stage 6+7 top: AXI-Lite load -> PL Decaps -> transcript KDF -> AEAD slot. */
module mlkem_secure_channel_axi_top #(
    parameter integer C_S_AXI_ADDR_WIDTH=8)(
    input logic s_axi_aclk,input logic s_axi_aresetn,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_awaddr,input logic s_axi_awvalid,
    output logic s_axi_awready,input logic[31:0]s_axi_wdata,input logic[3:0]s_axi_wstrb,
    input logic s_axi_wvalid,output logic s_axi_wready,output logic[1:0]s_axi_bresp,
    output logic s_axi_bvalid,input logic s_axi_bready,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_araddr,input logic s_axi_arvalid,
    output logic s_axi_arready,output logic[31:0]s_axi_rdata,output logic[1:0]s_axi_rresp,
    output logic s_axi_rvalid,input logic s_axi_rready,
    input logic[3:0]req_valid_i,output logic[3:0]req_ready_o,
    input logic[3:0]req_decrypt_i,input logic[31:0]req_data_len_i,
    input logic[255:0]req_counter_i,input logic[2047:0]req_data_i,
    input logic[511:0]req_tag_i,output logic[3:0]rsp_valid_o,
    input logic[3:0]rsp_ready_i,output logic[3:0]rsp_auth_ok_o,
    output logic[3:0]rsp_error_o,output logic[255:0]rsp_counter_o,
    output logic[2047:0]rsp_data_o,output logic[511:0]rsp_tag_o);
    typedef enum logic[3:0]{IDLE,D_START,D_WAIT,T_START,T_WAIT,K_START,K_WAIT,REPORT}st_t;
    st_t state;logic launch;logic[1:0]slot;logic[31:0]session;
    logic core_busy,core_done,core_fail,final_done,final_fail;
    logic[255:0]ss,transcript;logic ks,kbusy,kdone,thdone;
    logic eswe,ecwe,ewe;logic[8:0]eska,tska,ska;logic[7:0]ecta,tcta,cta;
    logic[11:0]epa;logic[31:0]eswd,ecwd,skr,ctr;logic[15:0]epd,pr;
    mlkem_decaps_axi_lite_frontend #(.C_S_AXI_ADDR_WIDTH(C_S_AXI_ADDR_WIDTH)) front(
        s_axi_aclk,s_axi_aresetn,s_axi_awaddr,s_axi_awvalid,s_axi_awready,
        s_axi_wdata,s_axi_wstrb,s_axi_wvalid,s_axi_wready,s_axi_bresp,s_axi_bvalid,s_axi_bready,
        s_axi_araddr,s_axi_arvalid,s_axi_arready,s_axi_rdata,s_axi_rresp,s_axi_rvalid,s_axi_rready,
        launch,slot,session,state!=IDLE,final_done,final_fail,
        eswe,ska,eswd,skr,ecwe,cta,ecwd,ctr,ewe,epa,epd,pr);
    mlkem512_decaps_engine dec(s_axi_aclk,s_axi_aresetn,state==D_START,core_busy,core_done,
        core_fail,ss,eswe,eska,eswd,skr,ecwe,ecta,ecwd,ctr,ewe,epa,epd,pr);
    mlkem_handshake_transcript_hash th(s_axi_aclk,s_axi_aresetn,state==T_START,session,,thdone,
        transcript,tska,skr,tcta,ctr);
    secure_channel_core channel(.clk_i(s_axi_aclk),.rst_ni(s_axi_aresetn),
        .handshake_start_i(state==K_START),.handshake_slot_i(slot),
        .handshake_session_id_i(session),.handshake_shared_secret_i(ss),
        .handshake_transcript_hash_i(transcript),.handshake_busy_o(kbusy),
        .handshake_done_o(kdone),.req_valid_i(req_valid_i),.req_ready_o(req_ready_o),
        .req_decrypt_i(req_decrypt_i),.req_data_len_i(req_data_len_i),
        .req_counter_i(req_counter_i),.req_data_i(req_data_i),.req_tag_i(req_tag_i),
        .rsp_valid_o(rsp_valid_o),.rsp_ready_i(rsp_ready_i),.rsp_auth_ok_o(rsp_auth_ok_o),
        .rsp_error_o(rsp_error_o),.rsp_counter_o(rsp_counter_o),
        .rsp_data_o(rsp_data_o),.rsp_tag_o(rsp_tag_o));
    always_comb begin
        ska=(state==T_START||state==T_WAIT)?tska:eska;
        cta=(state==T_START||state==T_WAIT)?tcta:ecta;
        final_done=state==REPORT;final_fail=core_fail;
    end
    always_ff @(posedge s_axi_aclk or negedge s_axi_aresetn)begin
        if(!s_axi_aresetn)state<=IDLE;else case(state)
          IDLE:if(launch)state<=D_START;D_START:state<=D_WAIT;
          D_WAIT:if(core_done)state<=core_fail?REPORT:T_START;
          T_START:state<=T_WAIT;T_WAIT:if(thdone)state<=K_START;
          K_START:state<=K_WAIT;K_WAIT:if(kdone)state<=REPORT;
          REPORT:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
