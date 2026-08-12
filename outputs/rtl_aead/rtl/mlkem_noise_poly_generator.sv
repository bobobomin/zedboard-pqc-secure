`timescale 1ns/1ps
/* PRF(seed,nonce) followed by CBD eta=2 or eta=3. */
module mlkem_noise_poly_generator(input logic clk_i,input logic rst_ni,input logic start_i,
    input logic[255:0]seed_i,input logic[7:0]nonce_i,input logic eta3_i,
    input logic[3:0]dst_slot_i,output logic busy_o,output logic done_o,
    output logic poly_we_o,output logic[11:0]poly_addr_o,output logic[15:0]poly_wdata_o);
    typedef enum logic[3:0]{IDLE,HSTART,FEED,FINAL,COLLECT,WRITE,DRAIN,DONE}st_t;st_t state;
    integer index,byte_count,coeff_count,write_index;logic[31:0]group;logic hs,hfin,iready,oval,hdone,oready;
    logic[7:0]obyte,inbyte;logic signed[127:0]e2;logic signed[63:0]e3;logic eta;logic[3:0]slot;
    mlkem_cbd_eta2_group c2(group,e2);mlkem_cbd_eta3_group c3(group[23:0],e3);
    sha3_shake_stream hash(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(hs),.mode_i(2'd3),
        .output_length_i(eta?16'd192:16'd128),.input_byte_i(inbyte),
        .input_valid_i(state==FEED),.input_ready_o(iready),.finalize_i(hfin),
        .output_byte_o(obyte),.output_valid_o(oval),.output_ready_i(oready),
        .busy_o(),.done_o(hdone));
    always_comb begin inbyte=index<32?seed_i[8*index+:8]:nonce_i;
        hs=state==HSTART;hfin=state==FINAL;oready=state==COLLECT||state==DRAIN;
        poly_we_o=state==WRITE;poly_addr_o=slot*256+coeff_count;
        poly_wdata_o=eta?e3[16*write_index+:16]:e2[16*write_index+:16];
        busy_o=state!=IDLE;done_o=state==DONE;end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;byte_count<=0;coeff_count<=0;
            write_index<=0;group<=0;eta<=0;slot<=0;end else case(state)
            IDLE:if(start_i)begin index<=0;byte_count<=0;coeff_count<=0;write_index<=0;
                group<=0;eta<=eta3_i;slot<=dst_slot_i;state<=HSTART;end
            HSTART:state<=FEED;
            FEED:if(iready)begin if(index==32)begin index<=0;state<=FINAL;end else index<=index+1;end
            FINAL:state<=COLLECT;
            COLLECT:if(oval)begin group[8*byte_count+:8]<=obyte;
                if(byte_count==(eta?2:3))begin byte_count<=0;write_index<=0;state<=WRITE;end
                else byte_count<=byte_count+1;end
            WRITE:begin if(coeff_count==255)state<=DONE;else begin coeff_count<=coeff_count+1;
                if(write_index==(eta?3:7))state<=COLLECT;else write_index<=write_index+1;end end
            DRAIN:if(hdone)state<=DONE;DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
