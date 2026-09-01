`timescale 1ns/1ps

/*
 * Fault-protected shared-resource top.
 * fault_inject_i is a verification-only diagnostic input:
 * [0] hash command bit flip, [1] shared-secret storage bit flip,
 * [2] transcript storage bit flip, [3] KDF-material storage bit flip,
 * [4] suppress hash completion toward the controller, [5] spurious response-valid.
 */
module mlkem_secure_channel_fault_protected_axi_top #(
    parameter integer C_S_AXI_ADDR_WIDTH=8,
    parameter integer MAX_STAGE_CYCLES=300000)(
    input logic s_axi_aclk,input logic s_axi_aresetn,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_awaddr,input logic s_axi_awvalid,
    output logic s_axi_awready,input logic[31:0]s_axi_wdata,input logic[3:0]s_axi_wstrb,
    input logic s_axi_wvalid,output logic s_axi_wready,output logic[1:0]s_axi_bresp,
    output logic s_axi_bvalid,input logic s_axi_bready,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_araddr,input logic s_axi_arvalid,
    output logic s_axi_arready,output logic[31:0]s_axi_rdata,output logic[1:0]s_axi_rresp,
    output logic s_axi_rvalid,input logic s_axi_rready,
    input logic[5:0]fault_inject_i,output logic fault_detected_o,output logic[7:0]fault_code_o,
    input logic[3:0]req_valid_i,output logic[3:0]req_ready_o,input logic[3:0]req_decrypt_i,
    input logic[31:0]req_data_len_i,input logic[255:0]req_counter_i,input logic[2047:0]req_data_i,
    input logic[511:0]req_tag_i,output logic[3:0]rsp_valid_o,input logic[3:0]rsp_ready_i,
    output logic[3:0]rsp_auth_ok_o,output logic[3:0]rsp_error_o,
    output logic[255:0]rsp_counter_o,output logic[2047:0]rsp_data_o,output logic[511:0]rsp_tag_o);
    localparam[7:0]F_SEQUENCE=8'h01,F_HASH=8'h02,F_SECRET=8'h04,F_TRANSCRIPT=8'h08,
        F_MATERIAL=8'h10,F_TIMEOUT=8'h20,F_OUTPUT=8'h40;
    typedef enum logic[3:0]{IDLE,D_START,D_WAIT,T_GUARD,T_START,T_WAIT,K_GUARD,
        K_START,K_WAIT,C_GUARD,C_START,C_WAIT,REPORT}st_t;st_t state,prev_state;
    logic launch;logic[1:0]slot;logic[31:0]session;logic core_done,core_fail,final_done,final_fail;
    logic[255:0]ss,ss_a,ss_b,transcript_a,transcript_b;logic[575:0]material_a,material_b,hdigest;
    logic eswe,ecwe,dpwe,hpwe,pwe;logic[8:0]dska,hska,ska;logic[7:0]dcta,hcta,cta;
    logic[11:0]dpa,hpa,pa;logic[31:0]eswd,ecwd,skr,ctr;logic[15:0]dpd,hpd,pd,pr;
    logic dhs,hs_req,hs_hash,hbusy,hdone_raw,hdone_ctl,herr,dheta,heta;
    logic[2:0]dhcmd,hcmd_req,hcmd_hash;logic[255:0]dhd0,dhd1,hd0,hd1;
    logic[7:0]dhx,dhy,dhnonce,hx,hy,hnonce;logic[3:0]dhslot,hslot;logic install_done,install_req;
    logic[4:0]hash_index;logic[19:0]stage_timer;logic[3:0]outstanding,mon_rsp_valid;
    /* Redundancy checks on 256- and 576-bit pairs.  Comparing them inside the
       state that gates the hash start puts the whole compare tree in front of
       the hash engine's load enable, so the result is registered and each
       check waits one clock in a *_GUARD state. */
    logic ss_match,transcript_match,material_match;
    logic[3:0]raw_rsp_valid,raw_rsp_auth,raw_rsp_error;logic[255:0]raw_rsp_counter;
    logic[2047:0]raw_rsp_data;logic[511:0]raw_rsp_tag;
    function automatic[2:0]expected_hash(input logic[4:0]n);begin
      case(n)0:expected_hash=0;1:expected_hash=1;
        2,3,4,5,6:expected_hash=4;7,8,9,10:expected_hash=3;
        11:expected_hash=2;12:expected_hash=5;default:expected_hash=6;endcase
    end endfunction
    mlkem_decaps_axi_lite_frontend #(.C_S_AXI_ADDR_WIDTH(C_S_AXI_ADDR_WIDTH)) front(
      s_axi_aclk,s_axi_aresetn,s_axi_awaddr,s_axi_awvalid,s_axi_awready,s_axi_wdata,s_axi_wstrb,
      s_axi_wvalid,s_axi_wready,s_axi_bresp,s_axi_bvalid,s_axi_bready,s_axi_araddr,s_axi_arvalid,
      s_axi_arready,s_axi_rdata,s_axi_rresp,s_axi_rvalid,s_axi_rready,launch,slot,session,state!=IDLE,
      final_done,final_fail,eswe,ska,eswd,skr,ecwe,cta,ecwd,ctr,pwe,pa,pd,pr);
    mlkem512_decaps_shared_engine dec(s_axi_aclk,s_axi_aresetn,state==D_START,,core_done,core_fail,ss,
      dhs,dhcmd,dhd0,dhd1,dhx,dhy,dhnonce,dheta,dhslot,hdone_ctl,herr,hdigest,
      eswe,dska,eswd,skr,ecwe,dcta,ecwd,ctr,dpwe,dpa,dpd,pr);
    mlkem_shared_hash_engine hash(s_axi_aclk,s_axi_aresetn,hs_hash,hcmd_hash,hd0,hd1,session,
      hx,hy,hnonce,heta,hslot,hbusy,hdone_raw,herr,hdigest,hska,skr,hcta,ctr,hpwe,hpa,hpd);
    secure_channel_material_core channel(s_axi_aclk,s_axi_aresetn,install_req,slot,session,material_a,
      ,install_done,req_valid_i,req_ready_o,req_decrypt_i,req_data_len_i,req_counter_i,req_data_i,
      req_tag_i,raw_rsp_valid,rsp_ready_i,raw_rsp_auth,raw_rsp_error,raw_rsp_counter,raw_rsp_data,raw_rsp_tag);
    always_comb begin
      hs_req=dhs;hcmd_req=dhcmd;hd0=dhd0;hd1=dhd1;hx=dhx;hy=dhy;hnonce=dhnonce;heta=dheta;hslot=dhslot;
      if(state==T_START)begin hs_req=!(fault_detected_o||!ss_match);hcmd_req=5;hd0=0;hd1=0;
        hx=0;hy=0;hnonce=0;heta=0;hslot=0;end
      else if(state==K_START)begin hs_req=!(fault_detected_o||!transcript_match);
        hcmd_req=6;hd0=ss_a;hd1=transcript_a;hx=0;hy=0;hnonce=0;heta=0;hslot=0;end
      hs_hash=hs_req;hcmd_hash=hcmd_req^{2'b00,fault_inject_i[0]};
      hdone_ctl=hdone_raw&~fault_inject_i[4];
      install_req=(state==C_START)&&!fault_detected_o&&material_match&&(hash_index==14);
      mon_rsp_valid=raw_rsp_valid;mon_rsp_valid[0]=raw_rsp_valid[0]|fault_inject_i[5];
      rsp_valid_o=mon_rsp_valid&outstanding;
      rsp_auth_ok_o=raw_rsp_auth&outstanding&{4{!fault_detected_o}};
      rsp_error_o=raw_rsp_error|({4{fault_detected_o}}&mon_rsp_valid);
      rsp_counter_o=raw_rsp_counter;rsp_tag_o=raw_rsp_tag;
      rsp_data_o=fault_detected_o?2048'd0:raw_rsp_data;
      ska=hbusy?hska:dska;cta=hbusy?hcta:dcta;pwe=hpwe|dpwe;pa=hpwe?hpa:dpa;pd=hpwe?hpd:dpd;
      final_done=state==REPORT;final_fail=core_fail|fault_detected_o;
    end
    always_ff @(posedge s_axi_aclk or negedge s_axi_aresetn)begin
      if(!s_axi_aresetn)begin state<=IDLE;prev_state<=IDLE;ss_a<=0;ss_b<=~256'd0;
        transcript_a<=0;transcript_b<=~256'd0;material_a<=0;material_b<=~576'd0;
        fault_detected_o<=0;fault_code_o<=0;hash_index<=0;stage_timer<=0;outstanding<=0;
        ss_match<=0;transcript_match<=0;material_match<=0;end
      else begin
        prev_state<=state;
        ss_match        <=(ss_a==~ss_b);
        transcript_match<=(transcript_a==~transcript_b);
        material_match  <=(material_a==~material_b);
        if(state!=prev_state)stage_timer<=0;else if(state!=IDLE&&state!=REPORT)stage_timer<=stage_timer+1;
        if(stage_timer>=MAX_STAGE_CYCLES-1)begin fault_detected_o<=1;fault_code_o<=fault_code_o|F_TIMEOUT;state<=REPORT;end
        if(hs_hash)begin
          if(hash_index>=14||hcmd_hash!=expected_hash(hash_index))begin
            fault_detected_o<=1;fault_code_o<=fault_code_o|F_SEQUENCE;end
          hash_index<=hash_index+1;
        end
        if(hdone_raw&&herr)begin fault_detected_o<=1;fault_code_o<=fault_code_o|F_HASH;end
        for(integer oi=0;oi<4;oi=oi+1)begin
          if(req_valid_i[oi]&&req_ready_o[oi])outstanding[oi]<=1;
          if(mon_rsp_valid[oi]&&!outstanding[oi])begin fault_detected_o<=1;
            fault_code_o<=fault_code_o|F_OUTPUT;end
          if(raw_rsp_valid[oi]&&rsp_ready_i[oi]&&outstanding[oi])outstanding[oi]<=0;
        end
        case(state)
          IDLE:if(launch)begin state<=D_START;fault_detected_o<=0;fault_code_o<=0;
            hash_index<=0;stage_timer<=0;end
          D_START:state<=D_WAIT;
          D_WAIT:if(core_done)begin ss_a<=ss^{255'd0,fault_inject_i[1]};ss_b<=~ss;
            if(hash_index!=12)begin fault_detected_o<=1;fault_code_o<=fault_code_o|F_SEQUENCE;end
            state<=core_fail?REPORT:T_GUARD;end
          T_GUARD:state<=T_START;
          T_START:begin if(fault_detected_o||!ss_match)begin fault_detected_o<=1;
              fault_code_o<=fault_code_o|F_SECRET;state<=REPORT;end else state<=T_WAIT;end
          T_WAIT:if(hdone_ctl)begin transcript_a<=hdigest[255:0]^{255'd0,fault_inject_i[2]};
            transcript_b<=~hdigest[255:0];state<=K_GUARD;end
          K_GUARD:state<=K_START;
          K_START:begin if(fault_detected_o||!transcript_match)begin fault_detected_o<=1;
              fault_code_o<=fault_code_o|F_TRANSCRIPT;state<=REPORT;end else state<=K_WAIT;end
          K_WAIT:if(hdone_ctl)begin material_a<=hdigest^{575'd0,fault_inject_i[3]};
            material_b<=~hdigest;state<=C_GUARD;end
          C_GUARD:state<=C_START;
          C_START:begin if(fault_detected_o||!material_match||(hash_index!=14))begin
              fault_detected_o<=1;fault_code_o<=fault_code_o|F_MATERIAL;state<=REPORT;end
            else state<=C_WAIT;end
          C_WAIT:if(install_done)state<=REPORT;
          REPORT:state<=IDLE;default:state<=IDLE;
        endcase
      end
    end
endmodule
