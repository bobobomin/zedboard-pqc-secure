`timescale 1ns/1ps
/* FIPS 203 G: SHA3-512 over exactly 64 bytes. */
module mlkem_hash_g(input logic clk_i,input logic rst_ni,input logic start_i,
    input logic[511:0]data_i,output logic busy_o,output logic done_o,
    output logic[511:0]digest_o);
    typedef enum logic[2:0]{IDLE,HSTART,FEED,FINAL,COLLECT,DONE}st_t;st_t state;
    integer index;logic hs,hfin,iready,oval,hdone;logic[7:0]obyte;
    sha3_shake_stream h(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(hs),.mode_i(2'd1),
        .output_length_i(16'd64),.input_byte_i(data_i[8*index+:8]),
        .input_valid_i(state==FEED),.input_ready_o(iready),.finalize_i(hfin),
        .output_byte_o(obyte),.output_valid_o(oval),.output_ready_i(1'b1),
        .busy_o(),.done_o(hdone));
    always_comb begin hs=state==HSTART;hfin=state==FINAL;busy_o=state!=IDLE;done_o=state==DONE;end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;digest_o<=0;end else case(state)
            IDLE:if(start_i)begin index<=0;digest_o<=0;state<=HSTART;end
            HSTART:state<=FEED;
            FEED:if(iready)begin if(index==63)begin index<=0;state<=FINAL;end
                else index<=index+1;end
            FINAL:begin index<=0;state<=COLLECT;end
            COLLECT:begin if(oval)begin digest_o[8*index+:8]<=obyte;
                if(index<63)index<=index+1;end if(hdone)state<=DONE;end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
