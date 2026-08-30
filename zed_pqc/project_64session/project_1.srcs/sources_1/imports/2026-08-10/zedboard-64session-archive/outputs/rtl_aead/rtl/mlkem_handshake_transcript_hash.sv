`timescale 1ns/1ps

/* SHA3-256(ek[800] || ciphertext[768] || session_id_be[4]). */
module mlkem_handshake_transcript_hash(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[31:0]session_id_i,
    output logic busy_o,output logic done_o,output logic[255:0]digest_o,
    output logic[8:0]sk_addr_o,input logic[31:0]sk_rdata_i,
    output logic[7:0]ct_addr_o,input logic[31:0]ct_rdata_i);
    typedef enum logic[3:0]{IDLE,HSTART,R_REQ,R_WAIT,R_CAP,FEED,FINAL,COLLECT,DONE}st_t;
    st_t state;integer index,out_index;logic hs,hfin,iready,oval,hdone;
    logic[7:0]inbyte,obyte,selected;
    sha3_shake_stream h(clk_i,rst_ni,hs,2'd0,16'd32,inbyte,state==FEED,iready,
        hfin,obyte,oval,1'b1,,hdone);
    always_comb begin
        sk_addr_o=(768+index)>>2;ct_addr_o=(index-800)>>2;
        selected=0;
        if(index<800)case((768+index)&3)0:selected=sk_rdata_i[7:0];
            1:selected=sk_rdata_i[15:8];2:selected=sk_rdata_i[23:16];default:selected=sk_rdata_i[31:24];endcase
        else if(index<1568)case((index-800)&3)0:selected=ct_rdata_i[7:0];
            1:selected=ct_rdata_i[15:8];2:selected=ct_rdata_i[23:16];default:selected=ct_rdata_i[31:24];endcase
        else case(index-1568)0:selected=session_id_i[31:24];1:selected=session_id_i[23:16];
            2:selected=session_id_i[15:8];default:selected=session_id_i[7:0];endcase
        hs=state==HSTART;hfin=state==FINAL;busy_o=state!=IDLE;done_o=state==DONE;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;out_index<=0;inbyte<=0;digest_o<=0;end
        else case(state)
          IDLE:if(start_i)begin index<=0;out_index<=0;digest_o<=0;state<=HSTART;end
          HSTART:state<=R_REQ;R_REQ:state<=R_WAIT;R_WAIT:state<=R_CAP;
          R_CAP:begin inbyte<=selected;state<=FEED;end
          FEED:if(iready)begin index<=index+1;if(index==1571)state<=FINAL;
              else if(index>=1567)begin
                  case(index+1-1568)0:inbyte<=session_id_i[31:24];1:inbyte<=session_id_i[23:16];
                    2:inbyte<=session_id_i[15:8];default:inbyte<=session_id_i[7:0];endcase
                  state<=FEED;end else state<=R_REQ;end
          FINAL:state<=COLLECT;
          COLLECT:begin if(oval)begin digest_o[8*out_index+:8]<=obyte;
              if(out_index<31)out_index<=out_index+1;end if(hdone)state<=DONE;end
          DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
