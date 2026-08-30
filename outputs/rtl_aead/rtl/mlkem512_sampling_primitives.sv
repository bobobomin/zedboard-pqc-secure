`timescale 1ns/1ps

module mlkem_cbd_eta2_group(input logic[31:0]bytes_i,
    output logic signed[127:0]coeffs_o);
    logic[31:0]d;integer i;logic[2:0]a,b;
    always_comb begin d=(bytes_i&32'h55555555)+((bytes_i>>1)&32'h55555555);
        coeffs_o=0;for(i=0;i<8;i=i+1)begin a=(d>>(4*i))&3;b=(d>>(4*i+2))&3;
            coeffs_o[16*i+:16]=$signed({1'b0,a})-$signed({1'b0,b});end end
endmodule

module mlkem_cbd_eta3_group(input logic[23:0]bytes_i,
    output logic signed[63:0]coeffs_o);
    logic[23:0]d;integer i;logic[3:0]a,b;
    always_comb begin d=(bytes_i&24'h249249)+((bytes_i>>1)&24'h249249)
        +((bytes_i>>2)&24'h249249);coeffs_o=0;
        for(i=0;i<4;i=i+1)begin a=(d>>(6*i))&7;b=(d>>(6*i+3))&7;
            coeffs_o[16*i+:16]=$signed({1'b0,a})-$signed({1'b0,b});end end
endmodule

module mlkem_rejection_pair(input logic[23:0]bytes_i,
    output logic[11:0]value0_o,output logic valid0_o,
    output logic[11:0]value1_o,output logic valid1_o);
    always_comb begin value0_o={bytes_i[11:8],bytes_i[7:0]};
        value1_o={bytes_i[23:16],bytes_i[15:12]};
        valid0_o=value0_o<12'd3329;valid1_o=value1_o<12'd3329;end
endmodule

module mlkem_coeff_addsub(input logic clk_i,input logic rst_ni,
    input logic signed[15:0]a_i,input logic signed[15:0]b_i,
    input logic subtract_i,output logic[15:0]canonical_o);
    logic signed[17:0]sum_reg,sum_delay_reg;logic signed[7:0]quotient_reg;
    logic signed[19:0]remainder_reg,x;
    always_ff @(posedge clk_i or negedge rst_ni)begin
        if(!rst_ni)begin sum_reg<=0;sum_delay_reg<=0;quotient_reg<=0;remainder_reg<=0;end
        else begin
            sum_reg<=subtract_i?a_i-b_i:a_i+b_i;
            sum_delay_reg<=sum_reg;
            quotient_reg<=(34'sd20159*sum_reg+34'sd33554432)>>>26;
            remainder_reg<=sum_delay_reg-quotient_reg*20'sd3329;
        end
    end
    always_comb begin x=remainder_reg;if(x<0)x=x+20'sd3329;canonical_o=x[15:0];end
endmodule
