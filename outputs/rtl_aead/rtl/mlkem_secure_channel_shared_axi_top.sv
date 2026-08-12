`timescale 1ns/1ps

/* Area-oriented top: one Keccak serves Decaps, transcript hashing, and traffic KDF. */
module mlkem_secure_channel_shared_axi_top #(parameter integer C_S_AXI_ADDR_WIDTH=8)(
    input logic s_axi_aclk,input logic s_axi_aresetn,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_awaddr,input logic s_axi_awvalid,
    output logic s_axi_awready,input logic[31:0]s_axi_wdata,input logic[3:0]s_axi_wstrb,
    input logic s_axi_wvalid,output logic s_axi_wready,output logic[1:0]s_axi_bresp,
    output logic s_axi_bvalid,input logic s_axi_bready,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_araddr,input logic s_axi_arvalid,
    output logic s_axi_arready,output logic[31:0]s_axi_rdata,output logic[1:0]s_axi_rresp,
    output logic s_axi_rvalid,input logic s_axi_rready,
    input logic[3:0]req_valid_i,output logic[3:0]req_ready_o,input logic[3:0]req_decrypt_i,
    input logic[31:0]req_data_len_i,input logic[255:0]req_counter_i,input logic[2047:0]req_data_i,
    input logic[511:0]req_tag_i,output logic[3:0]rsp_valid_o,input logic[3:0]rsp_ready_i,
    output logic[3:0]rsp_auth_ok_o,output logic[3:0]rsp_error_o,
    output logic[255:0]rsp_counter_o,output logic[2047:0]rsp_data_o,output logic[511:0]rsp_tag_o);
    typedef enum logic[3:0]{IDLE,D_START,D_WAIT,T_START,T_WAIT,K_START,K_WAIT,
        C_START,C_WAIT,REPORT}st_t;st_t state;
    logic launch;logic[1:0]slot;logic[31:0]session;logic core_done,core_fail,final_done,final_fail;
    logic[255:0]ss,transcript;logic[575:0]material,hdigest;
    logic eswe,ecwe,dpwe,hpwe,pwe;logic[8:0]dska,hska,ska;logic[7:0]dcta,hcta,cta;
    logic[11:0]dpa,hpa,pa;logic[31:0]eswd,ecwd,skr,ctr;logic[15:0]dpd,hpd,pd,pr;
    logic dhs,hs,hbusy,hdone,herr,dheta,heta;logic[2:0]dhcmd,hcmd;
    logic[255:0]dhd0,dhd1,hd0,hd1;logic[7:0]dhx,dhy,dhnonce,hx,hy,hnonce;
    logic[3:0]dhslot,hslot;logic install_done;
    mlkem_decaps_axi_lite_frontend #(.C_S_AXI_ADDR_WIDTH(C_S_AXI_ADDR_WIDTH)) front(
      s_axi_aclk,s_axi_aresetn,s_axi_awaddr,s_axi_awvalid,s_axi_awready,s_axi_wdata,s_axi_wstrb,
      s_axi_wvalid,s_axi_wready,s_axi_bresp,s_axi_bvalid,s_axi_bready,s_axi_araddr,s_axi_arvalid,
      s_axi_arready,s_axi_rdata,s_axi_rresp,s_axi_rvalid,s_axi_rready,launch,slot,session,state!=IDLE,
      final_done,final_fail,eswe,ska,eswd,skr,ecwe,cta,ecwd,ctr,pwe,pa,pd,pr);
    mlkem512_decaps_shared_engine dec(s_axi_aclk,s_axi_aresetn,state==D_START,,core_done,core_fail,ss,
      dhs,dhcmd,dhd0,dhd1,dhx,dhy,dhnonce,dheta,dhslot,hdone,herr,hdigest,
      eswe,dska,eswd,skr,ecwe,dcta,ecwd,ctr,dpwe,dpa,dpd,pr);
    mlkem_shared_hash_engine hash(s_axi_aclk,s_axi_aresetn,hs,hcmd,hd0,hd1,session,
      hx,hy,hnonce,heta,hslot,hbusy,hdone,herr,hdigest,hska,skr,hcta,ctr,hpwe,hpa,hpd);
    secure_channel_material_core channel(s_axi_aclk,s_axi_aresetn,state==C_START,slot,session,material,
      ,install_done,req_valid_i,req_ready_o,req_decrypt_i,req_data_len_i,req_counter_i,req_data_i,
      req_tag_i,rsp_valid_o,rsp_ready_i,rsp_auth_ok_o,rsp_error_o,rsp_counter_o,rsp_data_o,rsp_tag_o);
    always_comb begin
      hs=dhs;hcmd=dhcmd;hd0=dhd0;hd1=dhd1;hx=dhx;hy=dhy;hnonce=dhnonce;heta=dheta;hslot=dhslot;
      if(state==T_START)begin hs=1;hcmd=5;hd0=0;hd1=0;hx=0;hy=0;hnonce=0;heta=0;hslot=0;end
      else if(state==K_START)begin hs=1;hcmd=6;hd0=ss;hd1=transcript;hx=0;hy=0;hnonce=0;heta=0;hslot=0;end
      ska=hbusy?hska:dska;cta=hbusy?hcta:dcta;pwe=hpwe|dpwe;pa=hpwe?hpa:dpa;pd=hpwe?hpd:dpd;
      final_done=state==REPORT;final_fail=core_fail;
    end
    always_ff @(posedge s_axi_aclk or negedge s_axi_aresetn)begin
      if(!s_axi_aresetn)begin state<=IDLE;transcript<=0;material<=0;end else case(state)
        IDLE:if(launch)state<=D_START;D_START:state<=D_WAIT;
        D_WAIT:if(core_done)state<=core_fail?REPORT:T_START;
        T_START:state<=T_WAIT;T_WAIT:if(hdone)begin transcript<=hdigest[255:0];state<=K_START;end
        K_START:state<=K_WAIT;K_WAIT:if(hdone)begin material<=hdigest;state<=C_START;end
        C_START:state<=C_WAIT;C_WAIT:if(install_done)state<=REPORT;
        REPORT:state<=IDLE;default:state<=IDLE;
      endcase
    end
endmodule
