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
        DRAIN0,DRAIN1,FINAL_WRITE,DONE}st_t;
    st_t state;

    logic[7:0]index,write_offset;
    logic[3:0]sa,sb,sd;
    logic sub;
    logic signed[15:0]left;
    logic[15:0]result;

    mlkem_coeff_addsub u(
        clk_i,rst_ni,left,$signed(poly_rdata_i),sub,result
    );

    always_comb begin
        busy_o=state!=IDLE;
        done_o=state==DONE;
        poly_we_o=(state==ISSUE_WRITE&&index!=8'd0)||state==FINAL_WRITE;
        poly_wdata_o=result;

        write_offset=(index==8'd0)?8'd0:index-8'd1;

        case(state)
            READ_A:
                poly_addr_o={sa,index};
            READ_B:
                poly_addr_o={sb,index};
            ISSUE_WRITE:
                poly_addr_o={sd,write_offset};
            default:
                poly_addr_o={sd,8'hff};
        endcase
    end

    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin
            state<=IDLE;
            index<=8'd0;
            sa<=0;
            sb<=0;
            sd<=0;
            sub<=0;
            left<=0;
        end else case(state)
            IDLE:if(start_i)begin
                sa<=src_a_slot_i;
                sb<=src_b_slot_i;
                sd<=dst_slot_i;
                sub<=subtract_i;
                index<=8'd0;
                state<=READ_A;
            end
            READ_A:
                state<=READ_B;
            READ_B:begin
                left<=poly_rdata_i;
                state<=ISSUE_WRITE;
            end
            ISSUE_WRITE:
                if(index==8'hff)
                    state<=DRAIN0;
                else begin
                    index<=index+8'd1;
                    state<=READ_A;
                end
            DRAIN0:
                state<=DRAIN1;
            DRAIN1:
                state<=FINAL_WRITE;
            FINAL_WRITE:
                state<=DONE;
            DONE:
                state<=IDLE;
            default:
                state<=IDLE;
        endcase
    end
endmodule