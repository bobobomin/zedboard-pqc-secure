`timescale 1ns/1ps

/* Moves polynomial slots to/from the verified arithmetic kernel entirely in PL.
 *
 * The kernel keeps two bank halves.  This controller always loads into the half
 * the arithmetic is not using and flips set_o when that load is complete, so
 * the half just filled becomes the one under computation and the half that was
 * under computation becomes the one holding the result still to be stored.
 * One command can therefore compute while the previous result is stored and the
 * next operands are loaded.  ready_o says another command can be queued;
 * done_o still marks the point where everything issued has been stored, so a
 * caller that ignores ready_o keeps the original serial behaviour. */
module mlkem_poly_bridge_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[1:0]command_i,
    input logic[3:0]src_a_slot_i,input logic[3:0]src_b_slot_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic ready_o,output logic done_o,
    output logic poly_we_o,output logic[11:0]poly_addr_o,
    output logic[15:0]poly_wdata_o,input logic[15:0]poly_rdata_i
);
    /* Keep the numeric state ranges compatible with the cycle profiler:
       1..6 load, 7..8 core, 9..11 store, 12 done. */
    typedef enum logic[3:0]{IDLE=4'd0,LD_A=4'd1,LD_A_DRAIN=4'd2,
        LD_B=4'd3,LD_B_DRAIN=4'd4,LD_DONE=4'd5,GO=4'd6,CORE_GO=4'd7,
        OV_WAIT=4'd8,ST=4'd9,ST_DRAIN=4'd10,FLIP=4'd11,DONE=4'd12}st_t;st_t state;
    integer index,pipe_index;logic pipe_valid;
    logic set;
    /* Queued command, command whose operands are loaded and waiting, command in
       the kernel, and command whose result is still in the host half. */
    logic pend;logic[1:0]pend_cmd;logic[3:0]pend_sa,pend_sb,pend_sd;
    logic ld;logic[1:0]ld_cmd;logic[3:0]ld_sd;
    logic run,core_fin;logic[1:0]cmd;logic[3:0]sd;
    logic stq;logic[1:0]st_cmd;logic[3:0]st_sd;
    logic core_start,core_busy,core_done;
    logic core_we;logic[1:0]core_bank;logic[7:0]core_addr;logic signed[15:0]core_w,core_r;
    logic loading,storing;
    mlkem_poly_accelerator u_core(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(core_start),
        .command_i(cmd),.set_i(set),.busy_o(core_busy),.done_o(core_done),.host_we_i(core_we),
        .host_bank_i(core_bank),.host_addr_i(core_addr),.host_wdata_i(core_w),
        .host_rdata_o(core_r));
    always_comb begin
        loading=(state==LD_A||state==LD_A_DRAIN||state==LD_B||state==LD_B_DRAIN);
        storing=(state==ST||state==ST_DRAIN);
        core_start=(state==CORE_GO);
        core_we=pipe_valid&&loading;
        core_bank=(state==LD_B||state==LD_B_DRAIN)?2'd1:
            storing?((st_cmd==2'd2)?2'd2:2'd0):2'd0;
        core_addr=storing?index[7:0]:pipe_index[7:0];
        core_w=poly_rdata_i;
        poly_we_o=pipe_valid&&storing;
        poly_wdata_o=core_r;
        if(state==LD_A)poly_addr_o=pend_sa*256+index;
        else if(state==LD_B)poly_addr_o=pend_sb*256+index;
        else if(storing)poly_addr_o=st_sd*256+pipe_index;
        else poly_addr_o=0;
        busy_o=(state!=IDLE)||pend;
        /* Room for one more command while nothing is queued and nothing is
           already loaded, and only once a command is actually in the kernel to
           overlap with -- otherwise the trailing flush could be overtaken. */
        ready_o=!pend&&!ld&&(state==IDLE||run);
        done_o=(state==DONE);
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;pipe_index<=0;pipe_valid<=0;set<=0;
            pend<=0;pend_cmd<=0;pend_sa<=0;pend_sb<=0;pend_sd<=0;
            ld<=0;ld_cmd<=0;ld_sd<=0;run<=0;core_fin<=0;cmd<=0;sd<=0;
            stq<=0;st_cmd<=0;st_sd<=0;end
        else begin
            if(start_i&&ready_o)begin pend<=1;pend_cmd<=command_i;
                pend_sa<=src_a_slot_i;pend_sb<=src_b_slot_i;pend_sd<=dst_slot_i;end
            if(core_done)core_fin<=1;
            case(state)
            IDLE:if(pend)begin index<=0;pipe_index<=0;pipe_valid<=0;state<=LD_A;end
            LD_A:begin
                pipe_valid<=1;pipe_index<=index;
                if(index==255)state<=LD_A_DRAIN;else index<=index+1;
            end
            LD_A_DRAIN:begin
                pipe_valid<=0;index<=0;state<=(pend_cmd==2'd2)?LD_B:LD_DONE;
            end
            LD_B:begin
                pipe_valid<=1;pipe_index<=index;
                if(index==255)state<=LD_B_DRAIN;else index<=index+1;
            end
            LD_B_DRAIN:begin pipe_valid<=0;index<=0;state<=LD_DONE;end
            LD_DONE:begin
                ld<=1;ld_cmd<=pend_cmd;ld_sd<=pend_sd;pend<=0;
                state<=run?OV_WAIT:GO;
            end
            /* Flipping makes the half just loaded the one under computation and
               the half just computed the one whose result needs storing. */
            GO:begin
                set<=~set;cmd<=ld_cmd;sd<=ld_sd;run<=1;ld<=0;core_fin<=0;
                stq<=run;st_cmd<=cmd;st_sd<=sd;
                index<=0;pipe_index<=0;pipe_valid<=0;
                state<=CORE_GO;
            end
            CORE_GO:state<=stq?ST:OV_WAIT;
            ST:begin
                pipe_valid<=1;pipe_index<=index;
                if(index==255)state<=ST_DRAIN;else index<=index+1;
            end
            ST_DRAIN:begin
                pipe_valid<=0;index<=0;stq<=0;
                state<=run?OV_WAIT:DONE;
            end
            /* The kernel is running.  Take a queued command if one is waiting,
               otherwise launch the loaded one or flush the last result. */
            OV_WAIT:begin
                if(pend&&!ld)begin index<=0;pipe_index<=0;pipe_valid<=0;state<=LD_A;end
                else if(core_fin)state<=ld?GO:FLIP;
            end
            FLIP:begin
                set<=~set;stq<=1;st_cmd<=cmd;st_sd<=sd;run<=0;
                index<=0;pipe_index<=0;pipe_valid<=0;state<=ST;
            end
            DONE:state<=IDLE;default:state<=IDLE;
            endcase
        end
    end
endmodule
