`timescale 1ns/1ps
module mlkem_poly_addsub_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic subtract_i,
    input logic[3:0]src_a_slot_i,input logic[3:0]src_b_slot_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic done_o,output logic poly_we_o,
    output logic[11:0]poly_addr_o,output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i);
    /*
     * The polynomial RAM has one synchronous read/write port.  Schedule one
     * coefficient in three memory cycles: read A, read B, then write the
     * previous result while launching the current Barrett pipeline input.
     * The three reduction stages remain intact for timing, but their latency
     * is hidden behind the following coefficient's RAM reads.
     */
    typedef enum logic[3:0]{IDLE,READ_A,READ_B,ISSUE_WRITE,
        DRAIN0,DRAIN1,FINAL_WRITE,DONE}st_t;st_t state;
    integer index;logic[3:0]sa,sb,sd;logic sub;logic signed[15:0]left;
    logic[15:0]result;
    mlkem_coeff_addsub u(clk_i,rst_ni,left,$signed(poly_rdata_i),sub,result);
    always_comb begin
        busy_o=state!=IDLE;done_o=state==DONE;
        poly_we_o=(state==ISSUE_WRITE&&index!=0)||state==FINAL_WRITE;
        poly_wdata_o=result;
        case(state)
            READ_A:poly_addr_o=sa*256+index;
            READ_B:poly_addr_o=sb*256+index;
            ISSUE_WRITE:poly_addr_o=sd*256+(index==0?0:index-1);
            default:poly_addr_o=sd*256+255;
        endcase
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;sa<=0;sb<=0;sd<=0;sub<=0;left<=0;end
        else case(state)
            IDLE:if(start_i)begin sa<=src_a_slot_i;sb<=src_b_slot_i;sd<=dst_slot_i;
                sub<=subtract_i;index<=0;state<=READ_A;end
            READ_A:state<=READ_B;
            READ_B:begin left<=poly_rdata_i;state<=ISSUE_WRITE;end
            ISSUE_WRITE:if(index==255)state<=DRAIN0;
                else begin index<=index+1;state<=READ_A;end
            DRAIN0:state<=DRAIN1;
            DRAIN1:state<=FINAL_WRITE;
            FINAL_WRITE:state<=DONE;
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule

module mlkem_poly_tomsg_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[3:0]src_slot_i,
    output logic busy_o,output logic done_o,output logic[11:0]poly_addr_o,
    input logic[15:0]poly_rdata_i,output logic[255:0]message_o);
    typedef enum logic[2:0]{IDLE,READ,WAIT,DONE}st_t;st_t state;
    integer index;logic[3:0]slot;logic[31:0]p;
    always_comb begin poly_addr_o=slot*256+index;busy_o=state!=IDLE;done_o=state==DONE;
        p=poly_rdata_i*32'd1290168+32'h40000000;end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;slot<=0;message_o<=0;end
        else case(state)
            IDLE:if(start_i)begin slot<=src_slot_i;index<=0;message_o<=0;state<=READ;end
            READ:state<=WAIT;
            /* poly_rdata_i is valid in WAIT for the synchronous RAM read. */
            WAIT:begin message_o[index]<=p[31];if(index==255)state<=DONE;
                else begin index<=index+1;state<=READ;end end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
