`timescale 1ns/1ps

/* Moves polynomial slots to/from the verified arithmetic kernel entirely in PL. */
module mlkem_poly_bridge_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[1:0]command_i,
    input logic[3:0]src_a_slot_i,input logic[3:0]src_b_slot_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic done_o,
    output logic poly_we_o,output logic[11:0]poly_addr_o,
    output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i
);
    /* Keep the numeric state ranges compatible with the cycle profiler:
       1..6 load, 7..8 core, 9..11 store, 12 done. */
    typedef enum logic[3:0]{IDLE=4'd0,LOAD_A=4'd1,LOAD_A_DRAIN=4'd2,
        LOAD_B=4'd3,LOAD_B_DRAIN=4'd4,CORE_START=4'd7,CORE_WAIT=4'd8,
        STORE=4'd9,STORE_DRAIN=4'd10,DONE=4'd12}st_t;st_t state;
    integer index,pipe_index;logic pipe_valid;
    logic[1:0]cmd;logic[3:0]sa,sb,sd;logic core_start,core_busy,core_done;
    logic core_we;logic[1:0]core_bank;logic[7:0]core_addr;logic signed[15:0]core_w,core_r;
    mlkem_poly_accelerator u_core(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(core_start),
        .command_i(cmd),.busy_o(core_busy),.done_o(core_done),.host_we_i(core_we),
        .host_bank_i(core_bank),.host_addr_i(core_addr),.host_wdata_i(core_w),
        .host_rdata_o(core_r));
    always_comb begin
        core_start=(state==CORE_START);
        core_we=pipe_valid&&(state==LOAD_A||state==LOAD_A_DRAIN||
            state==LOAD_B||state==LOAD_B_DRAIN);
        core_bank=(state==LOAD_B||state==LOAD_B_DRAIN)?1:
            (state==STORE||state==STORE_DRAIN)?((cmd==2)?2:0):0;
        core_addr=(state==STORE||state==STORE_DRAIN)?index:pipe_index;
        core_w=poly_rdata_i;
        poly_we_o=pipe_valid&&(state==STORE||state==STORE_DRAIN);
        poly_wdata_o=core_r;
        if(state==LOAD_A)poly_addr_o=sa*256+index;
        else if(state==LOAD_B)poly_addr_o=sb*256+index;
        else if(state==STORE||state==STORE_DRAIN)poly_addr_o=sd*256+pipe_index;
        else poly_addr_o=0;
        busy_o=(state!=IDLE);done_o=(state==DONE);
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;pipe_index<=0;pipe_valid<=0;
            cmd<=0;sa<=0;sb<=0;sd<=0;end
        else case(state)
            IDLE:if(start_i)begin cmd<=command_i;sa<=src_a_slot_i;sb<=src_b_slot_i;
                sd<=dst_slot_i;index<=0;pipe_index<=0;pipe_valid<=0;state<=LOAD_A;end
            LOAD_A:begin
                pipe_valid<=1;pipe_index<=index;
                if(index==255)state<=LOAD_A_DRAIN;else index<=index+1;
            end
            LOAD_A_DRAIN:begin
                pipe_valid<=0;index<=0;state<=(cmd==2)?LOAD_B:CORE_START;
            end
            LOAD_B:begin
                pipe_valid<=1;pipe_index<=index;
                if(index==255)state<=LOAD_B_DRAIN;else index<=index+1;
            end
            LOAD_B_DRAIN:begin pipe_valid<=0;index<=0;state<=CORE_START;end
            CORE_START:state<=CORE_WAIT;
            CORE_WAIT:if(core_done)begin index<=0;pipe_index<=0;pipe_valid<=0;
                state<=STORE;end
            STORE:begin
                pipe_valid<=1;pipe_index<=index;
                if(index==255)state<=STORE_DRAIN;else index<=index+1;
            end
            STORE_DRAIN:begin pipe_valid<=0;state<=DONE;end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
