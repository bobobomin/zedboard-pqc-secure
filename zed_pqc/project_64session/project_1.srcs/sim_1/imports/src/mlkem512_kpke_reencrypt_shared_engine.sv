`timescale 1ns/1ps

/* K-PKE.Encrypt with matrix/noise SHAKE jobs issued to one external hash engine. */
module mlkem512_kpke_reencrypt_shared_engine(
    input logic clk_i,input logic rst_ni,input logic start_i,
    input logic[255:0]message_i,input logic[255:0]rho_i,input logic[255:0]coins_i,
    output logic busy_o,output logic done_o,output logic mismatch_o,
    output logic hash_start_o,output logic[2:0]hash_command_o,
    output logic[255:0]hash_data0_o,output logic[7:0]hash_x_o,output logic[7:0]hash_y_o,
    output logic[7:0]hash_nonce_o,output logic hash_eta3_o,output logic[3:0]hash_dst_slot_o,
    input logic hash_done_i,input logic hash_error_i,
    output logic[7:0]ct_addr_o,input logic[31:0]ct_rdata_i,
    output logic poly_we_o,output logic[11:0]poly_addr_o,
    output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i);
    localparam integer IDLE=0,FM_S=1,FM_W=2,
      NS0_S=3,NS0_W=4,NS1_S=5,NS1_W=6,NE0_S=7,NE0_W=8,
      NE1_S=9,NE1_W=10,NEP_S=11,NEP_W=12,NT0_S=13,NT0_W=14,NT1_S=15,NT1_W=16,
      M00_S=17,M00_W=18,B00_S=19,B00_W=20,M01_S=21,M01_W=22,B01_S=23,B01_W=24,
      AB0_S=25,AB0_W=26,IB0_S=27,IB0_W=28,EB0_S=29,EB0_W=30,CB0_S=31,CB0_W=32,
      M10_S=33,M10_W=34,B10_S=35,B10_W=36,M11_S=37,M11_W=38,B11_S=39,B11_W=40,
      AB1_S=41,AB1_W=42,IB1_S=43,IB1_W=44,EB1_S=45,EB1_W=46,CB1_S=47,CB1_W=48,
      VP0_S=49,VP0_W=50,VP1_S=51,VP1_W=52,VA_S=53,VA_W=54,VI_S=55,VI_W=56,
      VE_S=57,VE_W=58,VM_S=59,VM_W=60,CV_S=61,CV_W=62,DONE=63;
    logic[6:0]state;logic hash_fail_q;logic fs,fd,fwe;logic[11:0]fpa;logic[15:0]fpd;
    logic bs,bd,bwe;logic[1:0]bcmd;logic[3:0]bsa,bsb,bsd;logic[11:0]bpa;logic[15:0]bpd;
    logic as,ad,awe,sub;logic[3:0]asa,asb,asd;logic[11:0]apa;logic[15:0]apd;
    logic cs,cd,cclear,cmode,cmis;logic[3:0]cslot;logic[9:0]cbase;logic[11:0]cpa;logic[7:0]ccta;
    mlkem_poly_frommsg_controller frommsg(clk_i,rst_ni,fs,message_i,4'd7,,fd,fwe,fpa,fpd);
    mlkem_poly_bridge_controller bridge(clk_i,rst_ni,bs,bcmd,bsa,bsb,bsd,,bd,bwe,bpa,bpd,poly_rdata_i);
    mlkem_poly_addsub_controller addsub(clk_i,rst_ni,as,sub,asa,asb,asd,,ad,awe,apa,apd,poly_rdata_i);
    mlkem512_pack_compare_controller compare(clk_i,rst_ni,cs,cclear,cmode,cslot,cbase,,cd,cmis,cpa,poly_rdata_i,ccta,ct_rdata_i);
    function automatic logic in_pair(input integer s,input integer a,input integer b);
        in_pair=(s==a)||(s==b);endfunction
    always_comb begin
        fs=state==FM_S;
        hash_start_o=state==NS0_S||state==NS1_S||state==NE0_S||state==NE1_S||
            state==NEP_S||state==M00_S||state==M01_S||state==M10_S||state==M11_S;
        hash_command_o=(state>=M00_S)?3'd3:3'd4;hash_data0_o=(state>=M00_S)?rho_i:coins_i;
        hash_nonce_o=0;hash_eta3_o=0;hash_dst_slot_o=2;hash_x_o=0;hash_y_o=0;
        if(in_pair(state,NS0_S,NS0_W))hash_eta3_o=1;
        else if(in_pair(state,NS1_S,NS1_W))begin hash_nonce_o=1;hash_eta3_o=1;hash_dst_slot_o=3;end
        else if(in_pair(state,NE0_S,NE0_W))begin hash_nonce_o=2;hash_dst_slot_o=4;end
        else if(in_pair(state,NE1_S,NE1_W))begin hash_nonce_o=3;hash_dst_slot_o=5;end
        else if(in_pair(state,NEP_S,NEP_W))begin hash_nonce_o=4;hash_dst_slot_o=6;end
        if(in_pair(state,M00_S,M00_W))hash_dst_slot_o=8;
        else if(in_pair(state,M01_S,M01_W))begin hash_y_o=1;hash_dst_slot_o=8;end
        else if(in_pair(state,M10_S,M10_W))begin hash_x_o=1;hash_dst_slot_o=8;end
        else if(in_pair(state,M11_S,M11_W))begin hash_x_o=1;hash_y_o=1;hash_dst_slot_o=8;end
        bs=state==NT0_S||state==NT1_S||state==B00_S||state==B01_S||state==IB0_S||
           state==B10_S||state==B11_S||state==IB1_S||state==VP0_S||state==VP1_S||state==VI_S;
        bcmd=0;bsa=0;bsb=0;bsd=0;
        if(in_pair(state,NT0_S,NT0_W))begin bsa=2;bsd=2;end
        else if(in_pair(state,NT1_S,NT1_W))begin bsa=3;bsd=3;end
        else if(in_pair(state,B00_S,B00_W)||in_pair(state,B10_S,B10_W))begin bcmd=2;bsa=8;bsb=2;bsd=9;end
        else if(in_pair(state,B01_S,B01_W)||in_pair(state,B11_S,B11_W))begin bcmd=2;bsa=8;bsb=3;bsd=10;end
        else if(in_pair(state,IB0_S,IB0_W)||in_pair(state,IB1_S,IB1_W)||in_pair(state,VI_S,VI_W))begin bcmd=1;bsa=11;bsd=9;end
        else if(in_pair(state,VP0_S,VP0_W))begin bcmd=2;bsa=0;bsb=2;bsd=9;end
        else if(in_pair(state,VP1_S,VP1_W))begin bcmd=2;bsa=1;bsb=3;bsd=10;end
        as=state==AB0_S||state==EB0_S||state==AB1_S||state==EB1_S||state==VA_S||state==VE_S||state==VM_S;
        sub=0;asa=9;asb=10;asd=11;
        if(in_pair(state,EB0_S,EB0_W))begin asa=9;asb=4;asd=10;end
        else if(in_pair(state,EB1_S,EB1_W))begin asa=9;asb=5;asd=10;end
        else if(in_pair(state,VE_S,VE_W))begin asa=9;asb=6;asd=10;end
        else if(in_pair(state,VM_S,VM_W))begin asa=10;asb=7;asd=11;end
        cs=state==CB0_S||state==CB1_S||state==CV_S;cclear=in_pair(state,CB0_S,CB0_W);
        cmode=in_pair(state,CV_S,CV_W);cslot=10;cbase=0;
        if(in_pair(state,CB1_S,CB1_W))cbase=320;
        else if(in_pair(state,CV_S,CV_W))begin cslot=11;cbase=640;end
        ct_addr_o=ccta;
        if(state==FM_S||state==FM_W)begin poly_we_o=fwe;poly_addr_o=fpa;poly_wdata_o=fpd;end
        else if(bs||state==NT0_W||state==NT1_W||state==B00_W||state==B01_W||state==IB0_W||
          state==B10_W||state==B11_W||state==IB1_W||state==VP0_W||state==VP1_W||state==VI_W)begin
            poly_we_o=bwe;poly_addr_o=bpa;poly_wdata_o=bpd;end
        else if(as||state==AB0_W||state==EB0_W||state==AB1_W||state==EB1_W||state==VA_W||state==VE_W||state==VM_W)begin
            poly_we_o=awe;poly_addr_o=apa;poly_wdata_o=apd;end
        else begin poly_we_o=0;poly_addr_o=cpa;poly_wdata_o=0;end
        busy_o=state!=IDLE;done_o=state==DONE;mismatch_o=cmis|hash_fail_q;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
      if(!rst_ni)begin state<=IDLE;hash_fail_q<=0;end else begin
        if(hash_done_i&&hash_error_i)hash_fail_q<=1;
        case(state)
        IDLE:if(start_i)begin state<=FM_S;hash_fail_q<=0;end FM_S:state<=FM_W;FM_W:if(fd)state<=NS0_S;
        NS0_S:state<=NS0_W;NS0_W:if(hash_done_i)state<=NS1_S;NS1_S:state<=NS1_W;NS1_W:if(hash_done_i)state<=NE0_S;
        NE0_S:state<=NE0_W;NE0_W:if(hash_done_i)state<=NE1_S;NE1_S:state<=NE1_W;NE1_W:if(hash_done_i)state<=NEP_S;
        NEP_S:state<=NEP_W;NEP_W:if(hash_done_i)state<=NT0_S;NT0_S:state<=NT0_W;NT0_W:if(bd)state<=NT1_S;
        NT1_S:state<=NT1_W;NT1_W:if(bd)state<=M00_S;M00_S:state<=M00_W;M00_W:if(hash_done_i)state<=B00_S;
        B00_S:state<=B00_W;B00_W:if(bd)state<=M01_S;M01_S:state<=M01_W;M01_W:if(hash_done_i)state<=B01_S;
        B01_S:state<=B01_W;B01_W:if(bd)state<=AB0_S;AB0_S:state<=AB0_W;AB0_W:if(ad)state<=IB0_S;
        IB0_S:state<=IB0_W;IB0_W:if(bd)state<=EB0_S;EB0_S:state<=EB0_W;EB0_W:if(ad)state<=CB0_S;
        CB0_S:state<=CB0_W;CB0_W:if(cd)state<=M10_S;M10_S:state<=M10_W;M10_W:if(hash_done_i)state<=B10_S;
        B10_S:state<=B10_W;B10_W:if(bd)state<=M11_S;M11_S:state<=M11_W;M11_W:if(hash_done_i)state<=B11_S;
        B11_S:state<=B11_W;B11_W:if(bd)state<=AB1_S;AB1_S:state<=AB1_W;AB1_W:if(ad)state<=IB1_S;
        IB1_S:state<=IB1_W;IB1_W:if(bd)state<=EB1_S;EB1_S:state<=EB1_W;EB1_W:if(ad)state<=CB1_S;
        CB1_S:state<=CB1_W;CB1_W:if(cd)state<=VP0_S;VP0_S:state<=VP0_W;VP0_W:if(bd)state<=VP1_S;
        VP1_S:state<=VP1_W;VP1_W:if(bd)state<=VA_S;VA_S:state<=VA_W;VA_W:if(ad)state<=VI_S;
        VI_S:state<=VI_W;VI_W:if(bd)state<=VE_S;VE_S:state<=VE_W;VE_W:if(ad)state<=VM_S;
        VM_S:state<=VM_W;VM_W:if(ad)state<=CV_S;CV_S:state<=CV_W;CV_W:if(cd)state<=DONE;
        DONE:state<=IDLE;default:state<=IDLE;
        endcase
      end
    end
endmodule
