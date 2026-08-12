`timescale 1ns/1ps

/* Decode the embedded K-PKE public key and collect rho, H(ek), and z. */
module mlkem512_unpack_public_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,
    output logic busy_o,output logic done_o,
    output logic[8:0]sk_addr_o,input logic[31:0]sk_rdata_i,
    output logic poly_we_o,output logic[11:0]poly_addr_o,
    output logic[15:0]poly_wdata_o,
    output logic[255:0]rho_o,output logic[255:0]hpk_o,output logic[255:0]z_o);
    typedef enum logic[3:0]{IDLE,REQ,WAIT,CAPTURE,WRITE0,WRITE1,META_NEXT,DONE}st_t;
    st_t state;integer byte_index,group_index;logic[23:0]group;logic[31:0]coeffs;
    logic[7:0]selected_byte;
    mlkem_decode12_group dec(group,coeffs);
    always_comb begin
        sk_addr_o=byte_index>>2;
        case(byte_index[1:0])
            0:selected_byte=sk_rdata_i[7:0];1:selected_byte=sk_rdata_i[15:8];
            2:selected_byte=sk_rdata_i[23:16];default:selected_byte=sk_rdata_i[31:24];
        endcase
        poly_we_o=state==WRITE0||state==WRITE1;
        poly_addr_o=group_index*2+(state==WRITE1);
        poly_wdata_o=state==WRITE1?coeffs[31:16]:coeffs[15:0];
        busy_o=state!=IDLE;done_o=state==DONE;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;byte_index<=768;group_index<=0;group<=0;
            rho_o<=0;hpk_o<=0;z_o<=0;end else case(state)
            IDLE:if(start_i)begin byte_index<=768;group_index<=0;group<=0;
                rho_o<=0;hpk_o<=0;z_o<=0;state<=REQ;end
            REQ:state<=WAIT;WAIT:state<=CAPTURE;
            CAPTURE:begin
                if(byte_index<1536)begin
                    group[8*((byte_index-768)%3)+:8]<=selected_byte;
                    byte_index<=byte_index+1;
                    if(((byte_index-768)%3)==2)state<=WRITE0;else state<=REQ;
                end else begin
                    if(byte_index<1568)rho_o[8*(byte_index-1536)+:8]<=selected_byte;
                    else if(byte_index<1600)hpk_o[8*(byte_index-1568)+:8]<=selected_byte;
                    else z_o[8*(byte_index-1600)+:8]<=selected_byte;
                    byte_index<=byte_index+1;state<=META_NEXT;
                end
            end
            WRITE0:state<=WRITE1;
            WRITE1:begin group_index<=group_index+1;group<=0;
                if(byte_index==1536)state<=REQ;else state<=REQ;end
            META_NEXT:if(byte_index==1632)state<=DONE;else state<=REQ;
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule

/* FIPS 203 Decompress_1(message): one message bit becomes 0 or ceil(q/2). */
module mlkem_poly_frommsg_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,
    input logic[255:0]message_i,input logic[3:0]dst_slot_i,
    output logic busy_o,output logic done_o,output logic poly_we_o,
    output logic[11:0]poly_addr_o,output logic[15:0]poly_wdata_o);
    typedef enum logic[1:0]{IDLE,WRITE,DONE}st_t;st_t state;
    integer index;logic[3:0]slot;
    always_comb begin busy_o=state!=IDLE;done_o=state==DONE;poly_we_o=state==WRITE;
        poly_addr_o=slot*256+index;poly_wdata_o=message_i[index]?16'd1665:16'd0;end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;slot<=0;end else case(state)
            IDLE:if(start_i)begin index<=0;slot<=dst_slot_i;state<=WRITE;end
            WRITE:if(index==255)state<=DONE;else index<=index+1;
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule

/* Compress one polynomial and compare its serialized bytes to a CT range. */
module mlkem512_pack_compare_controller(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic clear_i,
    input logic mode_d4_i,input logic[3:0]src_slot_i,input logic[9:0]ct_base_i,
    output logic busy_o,output logic done_o,output logic mismatch_o,
    output logic[11:0]poly_addr_o,input logic[15:0]poly_rdata_i,
    output logic[7:0]ct_addr_o,input logic[31:0]ct_rdata_i);
    typedef enum logic[3:0]{IDLE,P_REQ,P_WAIT,P_CAP,C_PREP,C_REQ,C_WAIT,
        C_CHECK,NEXT_GROUP,DONE}st_t;st_t state;
    integer group_index,coeff_index,byte_index;logic mode;logic[3:0]slot;
    logic[9:0]base;logic[63:0]coeffs;logic[39:0]d10_bytes;logic[7:0]d4_byte;
    logic[7:0]expected,generated;logic mismatch,mismatch_bar;
    mlkem_compress_d10_group c10(coeffs,d10_bytes);
    mlkem_compress_d4_group c4(coeffs[31:0],d4_byte);
    always_comb begin
        poly_addr_o=slot*256+group_index*(mode?2:4)+coeff_index;
        ct_addr_o=(base+group_index*(mode?1:5)+byte_index)>>2;
        case((base+group_index*(mode?1:5)+byte_index)&3)
            0:expected=ct_rdata_i[7:0];1:expected=ct_rdata_i[15:8];
            2:expected=ct_rdata_i[23:16];default:expected=ct_rdata_i[31:24];
        endcase
        generated=mode?d4_byte:d10_bytes[8*byte_index+:8];
        busy_o=state!=IDLE;done_o=state==DONE;
        /* Dual-rail sticky compare: any disagreement or rail fault rejects. */
        mismatch_o=mismatch|~mismatch_bar|(mismatch==mismatch_bar);
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;group_index<=0;coeff_index<=0;byte_index<=0;
            mode<=0;slot<=0;base<=0;coeffs<=0;mismatch<=0;mismatch_bar<=1;end else case(state)
            IDLE:if(start_i)begin group_index<=0;coeff_index<=0;byte_index<=0;
                mode<=mode_d4_i;slot<=src_slot_i;base<=ct_base_i;coeffs<=0;
                if(clear_i)begin mismatch<=0;mismatch_bar<=1;end state<=P_REQ;end
            P_REQ:state<=P_WAIT;P_WAIT:state<=P_CAP;
            P_CAP:begin coeffs[16*coeff_index+:16]<=poly_rdata_i;
                if(coeff_index==(mode?1:3))begin coeff_index<=0;state<=C_PREP;end
                else begin coeff_index<=coeff_index+1;state<=P_REQ;end end
            C_PREP:begin byte_index<=0;state<=C_REQ;end
            C_REQ:state<=C_WAIT;C_WAIT:state<=C_CHECK;
            C_CHECK:begin mismatch<=mismatch|(expected!=generated);
                mismatch_bar<=mismatch_bar&(expected==generated);
                if(byte_index==(mode?0:4))state<=NEXT_GROUP;
                else begin byte_index<=byte_index+1;state<=C_REQ;end end
            NEXT_GROUP:begin
                if(group_index==(mode?127:63))state<=DONE;
                else begin group_index<=group_index+1;coeffs<=0;state<=P_REQ;end end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule

/* SHA3-256 over the embedded 800-byte public key, for the FIPS SK hash check. */
module mlkem512_public_key_hash(
    input logic clk_i,input logic rst_ni,input logic start_i,
    output logic busy_o,output logic done_o,output logic[255:0]digest_o,
    output logic[8:0]sk_addr_o,input logic[31:0]sk_rdata_i);
    typedef enum logic[3:0]{IDLE,HSTART,R_REQ,R_WAIT,R_CAP,FEED,FINAL,COLLECT,DONE}st_t;
    st_t state;integer byte_index,out_index;logic hs,hfin,iready,oval,hdone;
    logic[7:0]inbyte,obyte,selected;
    sha3_shake_stream h(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(hs),.mode_i(2'd0),
        .output_length_i(16'd32),.input_byte_i(inbyte),.input_valid_i(state==FEED),
        .input_ready_o(iready),.finalize_i(hfin),.output_byte_o(obyte),
        .output_valid_o(oval),.output_ready_i(1'b1),.busy_o(),.done_o(hdone));
    always_comb begin
        sk_addr_o=byte_index>>2;
        case(byte_index[1:0])0:selected=sk_rdata_i[7:0];1:selected=sk_rdata_i[15:8];
            2:selected=sk_rdata_i[23:16];default:selected=sk_rdata_i[31:24];endcase
        hs=state==HSTART;hfin=state==FINAL;busy_o=state!=IDLE;done_o=state==DONE;
    end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;byte_index<=768;out_index<=0;inbyte<=0;digest_o<=0;end
        else case(state)
            IDLE:if(start_i)begin byte_index<=768;out_index<=0;digest_o<=0;state<=HSTART;end
            HSTART:state<=R_REQ;R_REQ:state<=R_WAIT;R_WAIT:state<=R_CAP;
            R_CAP:begin inbyte<=selected;state<=FEED;end
            FEED:if(iready)begin byte_index<=byte_index+1;
                if(byte_index==1567)state<=FINAL;else state<=R_REQ;end
            FINAL:state<=COLLECT;
            COLLECT:begin if(oval)begin digest_o[8*out_index+:8]<=obyte;
                if(out_index<31)out_index<=out_index+1;end if(hdone)state<=DONE;end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule

/* FIPS 203 J(z || c): SHAKE256 over 32 + 768 bytes, output 32 bytes. */
module mlkem512_rejection_hash(
    input logic clk_i,input logic rst_ni,input logic start_i,input logic[255:0]z_i,
    output logic busy_o,output logic done_o,output logic[255:0]digest_o,
    output logic[7:0]ct_addr_o,input logic[31:0]ct_rdata_i);
    typedef enum logic[3:0]{IDLE,HSTART,CT_REQ,CT_WAIT,CT_CAP,FEED,FINAL,COLLECT,DONE}st_t;
    st_t state;integer index,out_index;logic hs,hfin,iready,oval,hdone;logic[7:0]inbyte,obyte,ctbyte;
    sha3_shake_stream h(.clk_i(clk_i),.rst_ni(rst_ni),.start_i(hs),.mode_i(2'd3),
        .output_length_i(16'd32),.input_byte_i(inbyte),.input_valid_i(state==FEED),
        .input_ready_o(iready),.finalize_i(hfin),.output_byte_o(obyte),
        .output_valid_o(oval),.output_ready_i(1'b1),.busy_o(),.done_o(hdone));
    always_comb begin ct_addr_o=(index-32)>>2;
        case((index-32)&3)0:ctbyte=ct_rdata_i[7:0];1:ctbyte=ct_rdata_i[15:8];
            2:ctbyte=ct_rdata_i[23:16];default:ctbyte=ct_rdata_i[31:24];endcase
        hs=state==HSTART;hfin=state==FINAL;busy_o=state!=IDLE;done_o=state==DONE;end
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin state<=IDLE;index<=0;out_index<=0;inbyte<=0;digest_o<=0;end
        else case(state)
            IDLE:if(start_i)begin index<=0;out_index<=0;digest_o<=0;state<=HSTART;end
            HSTART:begin inbyte<=z_i[7:0];state<=FEED;end
            FEED:if(iready)begin index<=index+1;
                if(index==799)state<=FINAL;
                else if(index<31)begin inbyte<=z_i[8*(index+1)+:8];state<=FEED;end
                else state<=CT_REQ;end
            CT_REQ:state<=CT_WAIT;CT_WAIT:state<=CT_CAP;
            CT_CAP:begin inbyte<=ctbyte;state<=FEED;end
            FINAL:state<=COLLECT;
            COLLECT:begin if(oval)begin digest_o[8*out_index+:8]<=obyte;
                if(out_index<31)out_index<=out_index+1;end if(hdone)state<=DONE;end
            DONE:state<=IDLE;default:state<=IDLE;
        endcase
    end
endmodule
