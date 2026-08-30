`timescale 1ns/1ps

/* Unpacks ML-KEM-512 ciphertext and the 768-byte K-PKE secret key. */
module mlkem512_unpack_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,
    output logic busy_o,output logic done_o,
    output logic [7:0] ct_word_addr_o,input logic [31:0] ct_word_i,
    output logic [8:0] sk_word_addr_o,input logic [31:0] sk_word_i,
    output logic poly_we_o,output logic [11:0] poly_addr_o,
    output logic [15:0] poly_wdata_o
);
    typedef enum logic[3:0]{IDLE,READ_REQ,READ_WAIT,
        WRITE_COEFF,NEXT_PHASE,DONE}st_t;st_t state;
    localparam logic[1:0] P_D10=0,P_D4=1,P_SK12=2;
    logic[1:0]phase;integer byte_index,group_count,group_index,write_index;
    logic[39:0]group_bytes;logic[63:0]d10_coeffs;logic[31:0]d4_coeffs,c12;
    logic[7:0]selected_byte;logic[2:0]group_size,coeff_count;
    mlkem_decompress_d10_group u_d10(group_bytes,d10_coeffs);
    mlkem_decompress_d4_group u_d4(group_bytes[7:0],d4_coeffs);
    mlkem_decode12_group u_12(group_bytes[23:0],c12);
    always_comb begin
        ct_word_addr_o=byte_index>>2;sk_word_addr_o=byte_index>>2;
        case(byte_index[1:0])
            0:selected_byte=(phase==P_SK12)?sk_word_i[7:0]:ct_word_i[7:0];
            1:selected_byte=(phase==P_SK12)?sk_word_i[15:8]:ct_word_i[15:8];
            2:selected_byte=(phase==P_SK12)?sk_word_i[23:16]:ct_word_i[23:16];
            default:selected_byte=(phase==P_SK12)?sk_word_i[31:24]:ct_word_i[31:24];
        endcase
        group_size=(phase==P_D10)?5:(phase==P_D4)?1:3;
        coeff_count=(phase==P_D10)?4:2;
        poly_we_o=(state==WRITE_COEFF);
        case(phase)
            P_D10:begin poly_addr_o=group_index*4+write_index;
                poly_wdata_o=d10_coeffs[16*write_index+:16];end
            P_D4:begin poly_addr_o=12'd512+group_index*2+write_index;
                poly_wdata_o=d4_coeffs[16*write_index+:16];end
            default:begin poly_addr_o=12'd768+group_index*2+write_index;
                poly_wdata_o=c12[16*write_index+:16];end
        endcase
        busy_o=(state!=IDLE);done_o=(state==DONE);
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;phase<=0;byte_index<=0;group_count<=0;
            group_index<=0;write_index<=0;group_bytes<=0;end
        else case(state)
            IDLE:if(start_i)begin phase<=P_D10;byte_index<=0;group_count<=0;
                group_index<=0;group_bytes<=0;state<=READ_REQ;end
            READ_REQ:state<=READ_WAIT;
            /* The source memories are synchronous: the word requested in
               READ_REQ is already valid throughout READ_WAIT.  Capture it
               here instead of spending a second, redundant wait cycle. */
            READ_WAIT:begin
                group_bytes[8*group_count+:8]<=selected_byte;
                byte_index<=byte_index+1;
                if(group_count==group_size-1)begin group_count<=0;write_index<=0;
                    state<=WRITE_COEFF;end
                else begin group_count<=group_count+1;state<=READ_REQ;end
            end
            WRITE_COEFF:begin
                if(write_index==coeff_count-1)begin
                    write_index<=0;group_index<=group_index+1;
                    if((phase==P_D10&&byte_index==640)||
                       (phase==P_D4&&byte_index==768)||
                       (phase==P_SK12&&byte_index==768))state<=NEXT_PHASE;
                    else state<=READ_REQ;
                end else write_index<=write_index+1;
            end
            NEXT_PHASE:begin
                group_bytes<=0;group_index<=0;group_count<=0;byte_index<=0;
                if(phase==P_D10)begin phase<=P_D4;byte_index<=640;state<=READ_REQ;end
                else if(phase==P_D4)begin phase<=P_SK12;state<=READ_REQ;end
                else state<=DONE;
            end
            DONE:state<=IDLE;
            default:state<=IDLE;
        endcase
    end
endmodule
