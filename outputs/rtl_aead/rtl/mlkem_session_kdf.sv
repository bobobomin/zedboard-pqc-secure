`timescale 1ns/1ps

/* SHAKE256("ZYNQ-PQC-v1" || ML-KEM shared secret || transcript hash, 72). */
module mlkem_session_kdf (
    input logic clk_i,input logic rst_ni,input logic start_i,
    input logic [255:0] shared_secret_i,input logic [255:0] transcript_hash_i,
    output logic busy_o,output logic done_o,
    output logic [255:0] pc_to_zb_key_o,output logic [31:0] pc_to_zb_prefix_o,
    output logic [255:0] zb_to_pc_key_o,output logic [31:0] zb_to_pc_prefix_o
);
    typedef enum logic [2:0] {K_IDLE,K_START,K_FEED,K_FINAL,K_COLLECT} kstate_t;
    kstate_t state;
    logic [6:0] index;
    logic [575:0] material;
    logic [255:0] secret_reg,hash_reg;
    logic hash_start,hash_finalize,hash_input_valid,hash_input_ready;
    logic [7:0] hash_input_byte,hash_output_byte;
    logic hash_output_valid,hash_done;

    always_comb begin
        hash_input_byte=0;
        case(index)
            0:hash_input_byte="Z";1:hash_input_byte="Y";2:hash_input_byte="N";
            3:hash_input_byte="Q";4:hash_input_byte="-";5:hash_input_byte="P";
            6:hash_input_byte="Q";7:hash_input_byte="C";8:hash_input_byte="-";
            9:hash_input_byte="v";10:hash_input_byte="1";
            default: begin
                if(index<43) hash_input_byte=secret_reg[8*(index-11)+:8];
                else hash_input_byte=hash_reg[8*(index-43)+:8];
            end
        endcase
    end
    assign hash_input_valid=(state==K_FEED);
    assign pc_to_zb_key_o=material[255:0];
    assign pc_to_zb_prefix_o=material[287:256];
    assign zb_to_pc_key_o=material[543:288];
    assign zb_to_pc_prefix_o=material[575:544];
    assign busy_o=(state!=K_IDLE);

    sha3_shake_stream u_hash(
        .clk_i(clk_i),.rst_ni(rst_ni),.start_i(hash_start),.mode_i(2'd3),
        .output_length_i(16'd72),.input_byte_i(hash_input_byte),
        .input_valid_i(hash_input_valid),.input_ready_o(hash_input_ready),
        .finalize_i(hash_finalize),.output_byte_o(hash_output_byte),
        .output_valid_o(hash_output_valid),.output_ready_i(1'b1),
        .busy_o(),.done_o(hash_done));

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if(!rst_ni) begin state<=K_IDLE;index<=0;material<=0;secret_reg<=0;
            hash_reg<=0;hash_start<=0;hash_finalize<=0;done_o<=0; end
        else begin
            hash_start<=0;hash_finalize<=0;done_o<=0;
            case(state)
                K_IDLE:if(start_i) begin secret_reg<=shared_secret_i;
                    hash_reg<=transcript_hash_i;material<=0;index<=0;state<=K_START;end
                K_START:begin hash_start<=1;state<=K_FEED;end
                K_FEED:if(hash_input_ready) begin
                    if(index==74) state<=K_FINAL; else index<=index+1;end
                K_FINAL:begin hash_finalize<=1;index<=0;state<=K_COLLECT;end
                K_COLLECT:begin
                    if(hash_output_valid) begin material[8*index+:8]<=hash_output_byte;
                        if(index<71)index<=index+1;end
                    if(hash_done) begin state<=K_IDLE;done_o<=1;end
                end
                default:state<=K_IDLE;
            endcase
        end
    end
endmodule
