`timescale 1ns/1ps

/* ML-KEM-512 codec primitives, FIPS 203 ByteEncode/Decode and Compress. */
module mlkem_decompress_d10_group(
    input logic [39:0] bytes_i, output logic [63:0] coeffs_o);
    logic [9:0] t0,t1,t2,t3;
    /* 3329 == 2^11 + 2^10 + 2^8 + 1, so the constant multiply is three adds
       and the result never leaves 22 bits.  Written as a 10x12 multiply this
       lands in a DSP that sits on the polynomial-memory write path. */
    function automatic [15:0] decomp(input logic [9:0] x);
        logic [21:0] p;
        begin p=({12'd0,x}<<11)+({12'd0,x}<<10)+({12'd0,x}<<8)+{12'd0,x}+22'd512;
            decomp={6'd0,p[21:10]};end
    endfunction
    always_comb begin
        t0={bytes_i[15:8],bytes_i[7:0]}&10'h3ff;
        t1={bytes_i[23:16],bytes_i[15:8]}>>2;
        t2={bytes_i[31:24],bytes_i[23:16]}>>4;
        t3={bytes_i[39:32],bytes_i[31:24]}>>6;
        coeffs_o={decomp(t3),decomp(t2),decomp(t1),decomp(t0)};
    end
endmodule

module mlkem_compress_d10_group(
    input logic [63:0] coeffs_i, output logic [39:0] bytes_o);
    logic [9:0] t[0:3];integer i;
    /* round(1024x/3329) for canonical x in [0,3328].  A 22-bit constant fits
       the 25-bit DSP port, so one DSP replaces the cascaded pair a 32-bit
       constant forces. */
    function automatic [9:0] comp(input logic [15:0] x);
        logic [33:0] p;begin p=x*22'd2580335;
            comp=((p+34'h40_0000)>>23)&10'h3ff;end
    endfunction
    always_comb begin
        for(i=0;i<4;i=i+1)t[i]=comp(coeffs_i[16*i+:16]);
        bytes_o[7:0]=t[0][7:0];
        bytes_o[15:8]={t[1][5:0],t[0][9:8]};
        bytes_o[23:16]={t[2][3:0],t[1][9:6]};
        bytes_o[31:24]={t[3][1:0],t[2][9:4]};
        bytes_o[39:32]=t[3][9:2];
    end
endmodule

module mlkem_decompress_d4_group(
    input logic [7:0] byte_i,output logic [31:0] coeffs_o);
    always_comb begin
        coeffs_o[15:0]=(byte_i[3:0]*16'd3329+16'd8)>>4;
        coeffs_o[31:16]=(byte_i[7:4]*16'd3329+16'd8)>>4;
    end
endmodule

module mlkem_compress_d4_group(
    input logic [31:0] coeffs_i,output logic [7:0] byte_o);
    /* round(16x/3329) for canonical x in [0,3328]; a 9-bit constant keeps the
       product inside 21 bits and out of the DSP columns entirely. */
    logic [20:0] p0,p1;
    always_comb begin
        p0=coeffs_i[15:0]*9'd315;
        p1=coeffs_i[31:16]*9'd315;
        byte_o[3:0]=(p0+21'h0_8000)>>16;
        byte_o[7:4]=(p1+21'h0_8000)>>16;
    end
endmodule

module mlkem_decode12_group(
    input logic [23:0] bytes_i,output logic [31:0] coeffs_o);
    always_comb begin
        coeffs_o[15:0]={4'd0,bytes_i[11:8],bytes_i[7:0]};
        coeffs_o[31:16]={4'd0,bytes_i[23:16],bytes_i[15:12]};
    end
endmodule

module mlkem_encode12_group(
    input logic [31:0] coeffs_i,output logic [23:0] bytes_o);
    always_comb begin
        bytes_o[7:0]=coeffs_i[7:0];
        bytes_o[15:8]={coeffs_i[19:16],coeffs_i[11:8]};
        bytes_o[23:16]=coeffs_i[27:20];
    end
endmodule

module mlkem_message_group(
    input logic [7:0] message_byte_i,
    output logic [127:0] message_coeffs_o,
    input logic [127:0] decoded_coeffs_i,
    output logic [7:0] decoded_byte_o);
    integer i;
    always_comb begin
        message_coeffs_o=0;decoded_byte_o=0;
        for(i=0;i<8;i=i+1)begin
            message_coeffs_o[16*i+:16]=message_byte_i[i]?16'd1665:16'd0;
            /* Compress_1: 1 exactly on 833..2496 for canonical coefficients. */
            decoded_byte_o[i]=(decoded_coeffs_i[16*i+:16]>=16'd833)&&
                              (decoded_coeffs_i[16*i+:16]<=16'd2496);
        end
    end
endmodule
