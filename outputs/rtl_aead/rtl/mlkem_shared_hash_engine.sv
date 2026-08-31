`timescale 1ns/1ps

/*
 * One SHA3/SHAKE datapath shared by every sequential ML-KEM and session hash.
 * Commands: 0 H(pk), 1 G(m||H(pk)), 2 J(z||ct), 3 matrix, 4 noise,
 *           5 transcript, 6 traffic KDF.
 */
module mlkem_shared_hash_engine(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[2:0]command_i,
    input logic[255:0]data0_i,input logic[255:0]data1_i,input logic[31:0]session_id_i,
    input logic[7:0]x_i,input logic[7:0]y_i,input logic[7:0]nonce_i,
    input logic eta3_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic done_o,output logic error_o,
    output logic[575:0]digest_o,
    output logic[8:0]sk_addr_o,input logic[31:0]sk_rdata_i,
    output logic[7:0]ct_addr_o,input logic[31:0]ct_rdata_i,
    output logic poly_we_o,output logic[11:0]poly_addr_o,output logic[15:0]poly_wdata_o);
    localparam[2:0]C_HPK=0,C_G=1,C_J=2,C_MATRIX=3,C_NOISE=4,C_TRANSCRIPT=5,C_KDF=6;
    typedef enum logic[4:0]{IDLE,HSTART,NEXT_IN,MEM_REQ,MEM_WAIT,MEM_CAP,FEED,
        FINAL,OUT,CHECK,W0,W1,NWRITE,DRAIN,DONE}st_t;st_t state;
    logic[2:0]cmd;logic[255:0]d0,d1;logic[31:0]sid;logic[7:0]x,y,nonce;
    logic eta;logic[3:0]slot;
    /* Widths follow the actual ranges: feeding these as 32-bit integers builds a
       32-bit decoder in front of every byte-indexed write below. */
    logic[10:0]in_index,input_len;logic[6:0]out_index;logic[1:0]byte_count;
    logic[7:0]coeff_count;logic[2:0]write_index;
    logic[31:0]group;logic[7:0]inbyte,obyte,mem_byte;logic hs,hfin,iready,oval,hdone,oready;
    logic[1:0]mode;logic[15:0]out_len;logic[11:0]rv0,rv1;logic rok0,rok1,hash_finished;
    logic signed[127:0]e2;logic signed[63:0]e3;
    mlkem_rejection_pair reject(group[23:0],rv0,rok0,rv1,rok1);
    mlkem_cbd_eta2_group cbd2(group,e2);mlkem_cbd_eta3_group cbd3(group[23:0],e3);
    sha3_shake_stream hash(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(hs),.mode_i(mode),
        .output_length_i(out_len),.input_byte_i(inbyte),.input_valid_i(state==FEED),
        .input_ready_o(iready),.finalize_i(hfin),.output_byte_o(obyte),
        .output_valid_o(oval),.output_ready_i(oready),.busy_o(),.done_o(hdone));
    function automatic logic memory_input(input logic[2:0]c,input logic[10:0]n);
        begin memory_input=(c==C_HPK)||((c==C_J)&&(n>=32))||
            ((c==C_TRANSCRIPT)&&(n<1568));end endfunction
    function automatic[7:0]domain_byte(input logic[10:0]n);begin case(n)
        0:domain_byte="Z";1:domain_byte="Y";2:domain_byte="N";3:domain_byte="Q";
        4:domain_byte="-";5:domain_byte="P";6:domain_byte="Q";7:domain_byte="C";
        8:domain_byte="-";9:domain_byte="v";default:domain_byte="1";endcase end endfunction
    always_comb begin
        mode=0;out_len=32;
        case(cmd)C_G:begin mode=1;out_len=64;end C_J:begin mode=3;out_len=32;end
          C_MATRIX:begin mode=2;out_len=1024;end C_NOISE:begin mode=3;out_len=eta?192:128;end
          C_KDF:begin mode=3;out_len=72;end default:begin end endcase
        sk_addr_o=0;ct_addr_o=0;mem_byte=0;
        if(cmd==C_HPK)begin sk_addr_o=(768+in_index)>>2;
            case((768+in_index)&3)0:mem_byte=sk_rdata_i[7:0];1:mem_byte=sk_rdata_i[15:8];
              2:mem_byte=sk_rdata_i[23:16];default:mem_byte=sk_rdata_i[31:24];endcase end
        else if(cmd==C_J)begin ct_addr_o=(in_index-32)>>2;
            case((in_index-32)&3)0:mem_byte=ct_rdata_i[7:0];1:mem_byte=ct_rdata_i[15:8];
              2:mem_byte=ct_rdata_i[23:16];default:mem_byte=ct_rdata_i[31:24];endcase end
        else if(cmd==C_TRANSCRIPT&&in_index<800)begin sk_addr_o=(768+in_index)>>2;
            case((768+in_index)&3)0:mem_byte=sk_rdata_i[7:0];1:mem_byte=sk_rdata_i[15:8];
              2:mem_byte=sk_rdata_i[23:16];default:mem_byte=sk_rdata_i[31:24];endcase end
        else if(cmd==C_TRANSCRIPT&&in_index<1568)begin ct_addr_o=(in_index-800)>>2;
            case((in_index-800)&3)0:mem_byte=ct_rdata_i[7:0];1:mem_byte=ct_rdata_i[15:8];
              2:mem_byte=ct_rdata_i[23:16];default:mem_byte=ct_rdata_i[31:24];endcase end
        hs=state==HSTART;hfin=state==FINAL;
        oready=state==OUT||state==DRAIN;
        poly_we_o=state==W0||state==W1||state==NWRITE;
        poly_addr_o=slot*256+coeff_count;
        if(state==W0)poly_wdata_o=rv0;else if(state==W1)poly_wdata_o=rv1;
        else poly_wdata_o=eta?e3[16*write_index+:16]:e2[16*write_index+:16];
        busy_o=state!=IDLE;done_o=state==DONE;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;cmd<=0;d0<=0;d1<=0;sid<=0;x<=0;y<=0;nonce<=0;
            eta<=0;slot<=0;in_index<=0;input_len<=0;out_index<=0;byte_count<=0;
            coeff_count<=0;write_index<=0;group<=0;inbyte<=0;digest_o<=0;error_o<=0;
            hash_finished<=0;end
        else begin
          if(hdone)hash_finished<=1;
          case(state)
          IDLE:if(start_i)begin cmd<=command_i;d0<=data0_i;d1<=data1_i;sid<=session_id_i;
              x<=x_i;y<=y_i;nonce<=nonce_i;eta<=eta3_i;slot<=dst_slot_i;
              in_index<=0;out_index<=0;byte_count<=0;coeff_count<=0;write_index<=0;
              group<=0;digest_o<=0;error_o<=0;hash_finished<=0;
              case(command_i)C_HPK:input_len<=11'd800;C_G:input_len<=11'd64;C_J:input_len<=11'd800;
                C_MATRIX:input_len<=11'd34;C_NOISE:input_len<=11'd33;C_TRANSCRIPT:input_len<=11'd1572;
                default:input_len<=11'd75;endcase state<=HSTART;end
          HSTART:state<=NEXT_IN;
          NEXT_IN:begin
              if(in_index==input_len)state<=FINAL;
              else if(memory_input(cmd,in_index))state<=MEM_REQ;
              else begin
                  case(cmd)
                    C_G:inbyte<=in_index<32?d0[8*in_index+:8]:d1[8*(in_index-32)+:8];
                    C_J:inbyte<=d0[8*in_index+:8];
                    C_MATRIX:inbyte<=in_index<32?d0[8*in_index+:8]:(in_index==32?x:y);
                    C_NOISE:inbyte<=in_index<32?d0[8*in_index+:8]:nonce;
                    C_TRANSCRIPT:case(in_index-1568)0:inbyte<=sid[31:24];1:inbyte<=sid[23:16];
                        2:inbyte<=sid[15:8];default:inbyte<=sid[7:0];endcase
                    default:begin if(in_index<11)inbyte<=domain_byte(in_index);
                        else if(in_index<43)inbyte<=d0[8*(in_index-11)+:8];
                        else inbyte<=d1[8*(in_index-43)+:8];end
                  endcase state<=FEED;end
          end
          MEM_REQ:state<=MEM_WAIT;MEM_WAIT:state<=MEM_CAP;
          MEM_CAP:begin inbyte<=mem_byte;state<=FEED;end
          FEED:if(iready)begin in_index<=in_index+11'd1;state<=NEXT_IN;end
          FINAL:begin out_index<=0;byte_count<=0;group<=0;state<=OUT;end
          OUT:if(oval)begin
              if(cmd==C_MATRIX||cmd==C_NOISE)begin group[8*byte_count+:8]<=obyte;
                  if(byte_count==(cmd==C_MATRIX?2'd2:(eta?2'd2:2'd3)))begin byte_count<=0;
                      write_index<=0;state<=cmd==C_MATRIX?CHECK:NWRITE;end
                  else byte_count<=byte_count+2'd1;end
              else begin digest_o[8*out_index+:8]<=obyte;if(out_index<7'd71)out_index<=out_index+7'd1;
                  if(hdone)state<=DONE;end
          end else if(hdone)begin if(cmd==C_MATRIX&&coeff_count<256)error_o<=1;state<=DONE;end
          CHECK:if(rok0)state<=W0;else if(rok1)state<=W1;else state<=OUT;
          W0:begin if(coeff_count==255)state<=DRAIN;else begin coeff_count<=coeff_count+8'd1;
              state<=rok1?W1:OUT;end end
          W1:begin if(coeff_count==255)state<=DRAIN;else begin coeff_count<=coeff_count+8'd1;state<=OUT;end end
          NWRITE:begin
              if(coeff_count==255)state<=DRAIN;else begin coeff_count<=coeff_count+8'd1;
                  if(write_index==(eta?3'd3:3'd7))begin write_index<=0;state<=OUT;end
                  else write_index<=write_index+3'd1;end end
          DRAIN:if(hdone||hash_finished)state<=DONE;
          DONE:state<=IDLE;default:state<=IDLE;
          endcase
        end
    end
endmodule
