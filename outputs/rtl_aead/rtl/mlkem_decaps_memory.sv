`timescale 1ns/1ps

/*
 * ML-KEM-512 Decaps storage.
 * SK:   408 x 32-bit = 1632 bytes, loaded once per key.
 * CT:   192 x 32-bit =  768 bytes, loaded once per session.
 * POLY: 3072 x 16-bit = twelve reusable polynomial slots.
 *
 * Port A is the AXI-Lite window. Port B belongs to the Decaps controller.
 */
module mlkem_decaps_memory(
    input logic clk_i,
    input logic host_valid_i,input logic host_we_i,input logic [1:0] host_region_i,
    input logic [11:0] host_addr_i,input logic [31:0] host_wdata_i,
    output logic [31:0] host_rdata_o,output logic host_ready_o,
    input logic sk_we_i,input logic [8:0] sk_addr_i,input logic [31:0] sk_wdata_i,
    output logic [31:0] sk_rdata_o,
    input logic ct_we_i,input logic [7:0] ct_addr_i,input logic [31:0] ct_wdata_i,
    output logic [31:0] ct_rdata_o,
    input logic poly_we_i,input logic [11:0] poly_addr_i,input logic [15:0] poly_wdata_i,
    output logic [15:0] poly_rdata_o
);
    (* ram_style="block" *) logic [31:0] sk_mem[0:511];
    (* ram_style="block" *) logic [31:0] ct_mem[0:255];
    (* ram_style="block" *) logic [15:0] poly_mem[0:3071];
    logic [31:0] host_sk_q,host_ct_q;logic [15:0] host_poly_q;
    logic [1:0] host_region_q;logic host_valid_q;

    always_ff @(posedge clk_i) begin
        if(host_valid_i&&host_we_i&&host_region_i==0)sk_mem[host_addr_i[8:0]]<=host_wdata_i;
        host_sk_q<=sk_mem[host_addr_i[8:0]];
    end
    always_ff @(posedge clk_i) begin
        if(sk_we_i)sk_mem[sk_addr_i]<=sk_wdata_i;
        sk_rdata_o<=sk_mem[sk_addr_i];
    end
    always_ff @(posedge clk_i) begin
        if(host_valid_i&&host_we_i&&host_region_i==1)ct_mem[host_addr_i[7:0]]<=host_wdata_i;
        host_ct_q<=ct_mem[host_addr_i[7:0]];
    end
    always_ff @(posedge clk_i) begin
        if(ct_we_i)ct_mem[ct_addr_i]<=ct_wdata_i;
        ct_rdata_o<=ct_mem[ct_addr_i];
    end
    always_ff @(posedge clk_i) begin
        if(host_valid_i&&host_we_i&&host_region_i==2)
            poly_mem[host_addr_i]<=host_wdata_i[15:0];
        host_poly_q<=poly_mem[host_addr_i];
    end
    always_ff @(posedge clk_i) begin
        if(poly_we_i)poly_mem[poly_addr_i]<=poly_wdata_i;
        poly_rdata_o<=poly_mem[poly_addr_i];
    end
    always_ff @(posedge clk_i)begin
        host_valid_q<=host_valid_i;host_region_q<=host_region_i;
    end
    always_comb begin
        case(host_region_q)
            0:host_rdata_o=host_sk_q;1:host_rdata_o=host_ct_q;
            2:host_rdata_o={16'd0,host_poly_q};default:host_rdata_o=0;
        endcase
        host_ready_o=host_valid_q;
    end
endmodule
