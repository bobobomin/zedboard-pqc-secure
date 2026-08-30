`timescale 1ns/1ps

/* Moves polynomial slots to/from the verified arithmetic kernel entirely in PL. */
module mlkem_poly_bridge_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[1:0]command_i,
    input logic[3:0]src_a_slot_i,input logic[3:0]src_b_slot_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic done_o,
    output logic poly_we_o,output logic[11:0]poly_addr_o,
    output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i
);
    typedef enum logic[3:0]{IDLE,LA_REQ,LA_WAIT,LA_WRITE,LB_REQ,LB_WAIT,LB_WRITE,
        CORE_START,CORE_WAIT,ST_REQ,ST_WAIT,ST_WRITE,DONE}st_t;st_t state;
    integer index;logic[1:0]cmd;logic[3:0]sa,sb,sd;logic core_start,core_busy,core_done;
    logic core_we;logic[1:0]core_bank;logic[7:0]core_addr;logic signed[15:0]core_w,core_r;
    mlkem_poly_accelerator u_core(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(core_start),
        .command_i(cmd),.busy_o(core_busy),.done_o(core_done),.host_we_i(core_we),
        .host_bank_i(core_bank),.host_addr_i(core_addr),.host_wdata_i(core_w),
        .host_rdata_o(core_r));
    always_comb begin
        core_start=(state==CORE_START);core_we=(state==LA_WRITE||state==LB_WRITE);
        core_bank=(state==LB_WRITE||state==LB_REQ||state==LB_WAIT)?1:
                  (state==ST_REQ||state==ST_WAIT||state==ST_WRITE)?((cmd==2)?2:0):0;
        core_addr=index;core_w=poly_rdata_i;
        poly_we_o=(state==ST_WRITE);poly_wdata_o=core_r;
        if(state==LA_REQ||state==LA_WAIT||state==LA_WRITE)poly_addr_o=sa*256+index;
        else if(state==LB_REQ||state==LB_WAIT||state==LB_WRITE)poly_addr_o=sb*256+index;
        else poly_addr_o=sd*256+index;
        busy_o=(state!=IDLE);done_o=(state==DONE);
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;cmd<=0;sa<=0;sb<=0;sd<=0;end
        else case(state)
            IDLE:if(start_i)begin cmd<=command_i;sa<=src_a_slot_i;sb<=src_b_slot_i;
                sd<=dst_slot_i;index<=0;state<=LA_REQ;end
            LA_REQ:state<=LA_WAIT;LA_WAIT:state<=LA_WRITE;
            LA_WRITE:if(index==255)begin index<=0;state<=(cmd==2)?LB_REQ:CORE_START;end
                else begin index<=index+1;state<=LA_REQ;end
            LB_REQ:state<=LB_WAIT;LB_WAIT:state<=LB_WRITE;
            LB_WRITE:if(index==255)begin index<=0;state<=CORE_START;end
                else begin index<=index+1;state<=LB_REQ;end
            CORE_START:state<=CORE_WAIT;
            CORE_WAIT:if(core_done)begin index<=0;state<=ST_REQ;end
            ST_REQ:state<=ST_WAIT;ST_WAIT:state<=ST_WRITE;
            ST_WRITE:if(index==255)state<=DONE;
                else begin index<=index+1;state<=ST_REQ;end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
