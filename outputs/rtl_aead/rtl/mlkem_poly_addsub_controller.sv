`timescale 1ns/1ps
module mlkem_poly_addsub_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic subtract_i,
    input logic[3:0]src_a_slot_i,input logic[3:0]src_b_slot_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic done_o,output logic poly_we_o,
    output logic[11:0]poly_addr_o,output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i);
    typedef enum logic[3:0]{IDLE,AR,AW,AC,BR,BW,BC,WRITE,DONE}st_t;st_t state;
    integer index;logic[3:0]sa,sb,sd;logic sub;logic signed[15:0]left,right;logic[15:0]result;
    mlkem_coeff_addsub u(left,right,sub,result);
    always_comb begin busy_o=state!=IDLE;done_o=state==DONE;poly_we_o=state==WRITE;
        poly_wdata_o=result;if(state==AR||state==AW||state==AC)poly_addr_o=sa*256+index;
        else if(state==BR||state==BW||state==BC)poly_addr_o=sb*256+index;
        else poly_addr_o=sd*256+index;end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;sa<=0;sb<=0;sd<=0;sub<=0;left<=0;right<=0;end
        else case(state)
            IDLE:if(start_i)begin sa<=src_a_slot_i;sb<=src_b_slot_i;sd<=dst_slot_i;
                sub<=subtract_i;index<=0;state<=AR;end
            AR:state<=AW;AW:state<=AC;AC:begin left<=poly_rdata_i;state<=BR;end
            BR:state<=BW;BW:state<=BC;BC:begin right<=poly_rdata_i;state<=WRITE;end
            WRITE:if(index==255)state<=DONE;else begin index<=index+1;state<=AR;end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule

module mlkem_poly_tomsg_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[3:0]src_slot_i,
    output logic busy_o,output logic done_o,output logic[11:0]poly_addr_o,
    input logic[15:0]poly_rdata_i,output logic[255:0]message_o);
    typedef enum logic[2:0]{IDLE,READ,WAIT,CAPTURE,DONE}st_t;st_t state;
    integer index;logic[3:0]slot;logic[31:0]p;
    always_comb begin poly_addr_o=slot*256+index;busy_o=state!=IDLE;done_o=state==DONE;
        p=poly_rdata_i*32'd1290168+32'h40000000;end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;slot<=0;message_o<=0;end
        else case(state)
            IDLE:if(start_i)begin slot<=src_slot_i;index<=0;message_o<=0;state<=READ;end
            READ:state<=WAIT;WAIT:state<=CAPTURE;
            CAPTURE:begin message_o[index]<=p[31];if(index==255)state<=DONE;
                else begin index<=index+1;state<=READ;end end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
