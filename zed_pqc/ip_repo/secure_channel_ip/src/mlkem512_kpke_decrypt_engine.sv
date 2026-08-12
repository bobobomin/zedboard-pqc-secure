`timescale 1ns/1ps

/* Complete ML-KEM-512 K-PKE.Decrypt datapath over shared polynomial slots. */
module mlkem512_kpke_decrypt_engine(
    input logic clk_i,input logic rst_ni,input logic start_i,
    output logic busy_o,output logic done_o,output logic[255:0]message_o,
    output logic[7:0]ct_addr_o,input logic[31:0]ct_rdata_i,
    output logic[8:0]sk_addr_o,input logic[31:0]sk_rdata_i,
    output logic poly_we_o,output logic[11:0]poly_addr_o,
    output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i,
    output logic operation_fault_o);
    typedef enum logic[4:0]{IDLE,U_START,U_WAIT,N0_START,N0_WAIT,N1_START,N1_WAIT,
        B0_START,B0_WAIT,B1_START,B1_WAIT,A_START,A_WAIT,I_START,I_WAIT,
        S_START,S_WAIT,M_START,M_WAIT,DONE}st_t;st_t state;
    logic us,ud,uw,bstart,bd,bwe,astart,ad,awe,mstart,md;
    logic[11:0]upa,bpa,apa,mpa;logic[15:0]upd,bpd,apd;logic[255:0]msg;
    logic[1:0]bcmd;logic[3:0]bsa,bsb,bsd,asa,asb,asd;logic subtract;
    logic uwe;logic[1:0]forward_count,multiply_count;logic inverse_seen;
    mlkem512_unpack_controller unpack(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(us),
        .busy_o(uw),.done_o(ud),.ct_word_addr_o(ct_addr_o),.ct_word_i(ct_rdata_i),
        .sk_word_addr_o(sk_addr_o),.sk_word_i(sk_rdata_i),.poly_we_o(uwe),
        .poly_addr_o(upa),.poly_wdata_o(upd));
    mlkem_poly_bridge_controller bridge(.clk_i(clk_i),.rst_ni(rst_ni),
        .start_i(bstart),.command_i(bcmd),.src_a_slot_i(bsa),.src_b_slot_i(bsb),
        .dst_slot_i(bsd),.busy_o(),.done_o(bd),.poly_we_o(bwe),.poly_addr_o(bpa),
        .poly_wdata_o(bpd),.poly_rdata_i(poly_rdata_i));
    mlkem_poly_addsub_controller addsub(.clk_i(clk_i),.rst_ni(rst_ni),
        .start_i(astart),.subtract_i(subtract),.src_a_slot_i(asa),.src_b_slot_i(asb),
        .dst_slot_i(asd),.busy_o(),.done_o(ad),.poly_we_o(awe),.poly_addr_o(apa),
        .poly_wdata_o(apd),.poly_rdata_i(poly_rdata_i));
    mlkem_poly_tomsg_controller tomsg(.clk_i(clk_i),.rst_ni(rst_ni),
        .start_i(mstart),.src_slot_i(4'd11),.busy_o(),.done_o(md),
        .poly_addr_o(mpa),.poly_rdata_i(poly_rdata_i),.message_o(msg));
    always_comb begin
        us=state==U_START;bstart=state==N0_START||state==N1_START||state==B0_START||
            state==B1_START||state==I_START;astart=state==A_START||state==S_START;
        mstart=state==M_START;bcmd=0;bsa=0;bsb=0;bsd=0;asa=0;asb=0;asd=0;subtract=0;
        case(state)
            N0_START,N0_WAIT:begin bcmd=0;bsa=0;bsd=5;end
            N1_START,N1_WAIT:begin bcmd=0;bsa=1;bsd=6;end
            B0_START,B0_WAIT:begin bcmd=2;bsa=3;bsb=5;bsd=7;end
            B1_START,B1_WAIT:begin bcmd=2;bsa=4;bsb=6;bsd=8;end
            A_START,A_WAIT:begin asa=7;asb=8;asd=9;subtract=0;end
            I_START,I_WAIT:begin bcmd=1;bsa=9;bsd=10;end
            S_START,S_WAIT:begin asa=2;asb=10;asd=11;subtract=1;end
            default:begin end
        endcase
        if(state==U_START||state==U_WAIT)begin poly_we_o=uwe;poly_addr_o=upa;poly_wdata_o=upd;end
        else if(state==N0_START||state==N0_WAIT||state==N1_START||state==N1_WAIT||
          state==B0_START||state==B0_WAIT||state==B1_START||state==B1_WAIT||
          state==I_START||state==I_WAIT)begin poly_we_o=bwe;poly_addr_o=bpa;poly_wdata_o=bpd;end
        else if(state==A_START||state==A_WAIT||state==S_START||state==S_WAIT)begin
            poly_we_o=awe;poly_addr_o=apa;poly_wdata_o=apd;end
        else begin poly_we_o=0;poly_addr_o=mpa;poly_wdata_o=0;end
        operation_fault_o=(forward_count!=2)||(multiply_count!=2)||!inverse_seen;
        busy_o=state!=IDLE;done_o=state==DONE;message_o=operation_fault_o?256'd0:msg;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;forward_count<=0;multiply_count<=0;inverse_seen<=0;end
        else begin
          if(state==N0_START||state==N1_START)forward_count<=forward_count+1;
          if(state==B0_START||state==B1_START)multiply_count<=multiply_count+1;
          if(state==I_START)inverse_seen<=1;
          case(state)
            IDLE:if(start_i)begin state<=U_START;forward_count<=0;multiply_count<=0;inverse_seen<=0;end
            U_START:state<=U_WAIT;U_WAIT:if(ud)state<=N0_START;
            N0_START:state<=N0_WAIT;N0_WAIT:if(bd)state<=N1_START;
            N1_START:state<=N1_WAIT;N1_WAIT:if(bd)state<=B0_START;
            B0_START:state<=B0_WAIT;B0_WAIT:if(bd)state<=B1_START;
            B1_START:state<=B1_WAIT;B1_WAIT:if(bd)state<=A_START;
            A_START:state<=A_WAIT;A_WAIT:if(ad)state<=I_START;
            I_START:state<=I_WAIT;I_WAIT:if(bd)state<=S_START;
            S_START:state<=S_WAIT;S_WAIT:if(ad)state<=M_START;
            M_START:state<=M_WAIT;M_WAIT:if(md)state<=DONE;
            DONE:state<=IDLE;default:state<=IDLE;
          endcase
        end
    end
endmodule
