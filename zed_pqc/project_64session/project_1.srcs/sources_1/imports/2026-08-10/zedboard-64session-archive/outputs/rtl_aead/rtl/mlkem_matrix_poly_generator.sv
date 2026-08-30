`timescale 1ns/1ps
/* SHAKE128 rejection sampler for one ML-KEM matrix polynomial. */
module mlkem_matrix_poly_generator(input logic clk_i,input logic rst_ni,input logic start_i,
    input logic[255:0]seed_i,input logic[7:0]x_i,input logic[7:0]y_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic done_o,output logic error_o,
    output logic poly_we_o,output logic[11:0]poly_addr_o,output logic[15:0]poly_wdata_o);
    typedef enum logic[3:0]{IDLE,HSTART,FEED,FINAL,COLLECT,CHECK,W0,W1,DRAIN,DONE}st_t;st_t state;
    integer index,byte_count,coeff_count;logic[23:0]group;logic hs,hfin,iready,oval,hdone,oready;
    logic[7:0]obyte,inbyte;logic[11:0]v0,v1;logic ok0,ok1;logic[3:0]slot;
    mlkem_rejection_pair pair(group,v0,ok0,v1,ok1);
    sha3_shake_stream hash(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(hs),.mode_i(2'd2),
        .output_length_i(16'd1024),.input_byte_i(inbyte),.input_valid_i(state==FEED),
        .input_ready_o(iready),.finalize_i(hfin),.output_byte_o(obyte),
        .output_valid_o(oval),.output_ready_i(oready),.busy_o(),.done_o(hdone));
    always_comb begin
        inbyte=index<32?seed_i[8*index+:8]:(index==32?x_i:y_i);
        hs=state==HSTART;hfin=state==FINAL;oready=state==COLLECT||state==DRAIN;
        poly_we_o=state==W0||state==W1;poly_addr_o=slot*256+coeff_count;
        poly_wdata_o=state==W0?v0:v1;busy_o=state!=IDLE;done_o=state==DONE;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;byte_count<=0;coeff_count<=0;
            group<=0;slot<=0;error_o<=0;end else case(state)
            IDLE:if(start_i)begin slot<=dst_slot_i;index<=0;byte_count<=0;
                coeff_count<=0;group<=0;error_o<=0;state<=HSTART;end
            HSTART:state<=FEED;
            FEED:if(iready)begin if(index==33)begin index<=0;state<=FINAL;end else index<=index+1;end
            FINAL:state<=COLLECT;
            COLLECT:if(oval)begin group[8*byte_count+:8]<=obyte;
                if(byte_count==2)begin byte_count<=0;state<=CHECK;end else byte_count<=byte_count+1;end
            CHECK:if(ok0)state<=W0;else if(ok1)state<=W1;else state<=COLLECT;
            W0:begin if(coeff_count==255)state<=DRAIN;else begin coeff_count<=coeff_count+1;
                state<=ok1?W1:COLLECT;end end
            W1:begin if(coeff_count==255)state<=DRAIN;else begin coeff_count<=coeff_count+1;
                state<=COLLECT;end end
            DRAIN:if(hdone)state<=DONE;
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
