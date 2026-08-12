`timescale 1ns/1ps

/* ML-KEM-512 codec primitives, FIPS 203 ByteEncode/Decode and Compress. */
module mlkem_decompress_d10_group(
    input logic [39:0] bytes_i, output logic [63:0] coeffs_o);
    logic [9:0] t0,t1,t2,t3;
    function automatic [15:0] decomp(input logic [9:0] x);
        logic [31:0] p;begin p=x*32'd3329+32'd512;decomp=p>>10;end
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
    function automatic [9:0] comp(input logic [15:0] x);
        logic [63:0] p;begin p=x*64'd2642263040;
            comp=((p+64'h1_0000_0000)>>33)&10'h3ff;end
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
    logic [31:0] p0,p1;
    always_comb begin
        p0=coeffs_i[15:0]*32'd1290160;
        p1=coeffs_i[31:16]*32'd1290160;
        byte_o[3:0]=(p0+32'h08000000)>>28;
        byte_o[7:4]=(p1+32'h08000000)>>28;
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
    integer i;logic [31:0] product;
    always_comb begin
        message_coeffs_o=0;decoded_byte_o=0;
        for(i=0;i<8;i=i+1)begin
            message_coeffs_o[16*i+:16]=message_byte_i[i]?16'd1665:16'd0;
            product=decoded_coeffs_i[16*i+:16]*32'd1290168;
            decoded_byte_o[i]=(product+32'h40000000)>>31;
        end
    end
endmodule
