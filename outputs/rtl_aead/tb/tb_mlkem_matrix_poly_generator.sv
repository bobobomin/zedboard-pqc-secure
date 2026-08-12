`timescale 1ns/1ps
module tb_mlkem_matrix_poly_generator;logic clk=0,rst=0,start,busy,done,err,we;
    logic[255:0]seed;logic[11:0]addr;logic[15:0]data;logic[15:0]poly[0:255];integer i;
    always #5 clk=~clk;always_ff @(posedge clk)if(we)poly[addr]<=data;
    function automatic[255:0]pack32(input[255:0]x);integer j;begin
        for(j=0;j<32;j=j+1)pack32[8*j+:8]=x[255-8*j-:8];end endfunction
    mlkem_matrix_poly_generator dut(clk,rst,start,seed,8'd0,8'd0,4'd0,
        busy,done,err,we,addr,data);
    initial begin start=0;seed=pack32(256'h344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c);
        repeat(3)@(posedge clk);rst=1;@(posedge clk);start=1;@(posedge clk);#1;start=0;
        wait(done);#1;if(poly[0]!=55||poly[1]!=1049||poly[2]!=656||poly[3]!=1808||
          poly[4]!=2188||poly[5]!=3277||poly[6]!=1266||poly[7]!=174)$fatal(1,"matrix sampler");
        $display("ALL ML-KEM MATRIX GENERATOR TESTS PASSED");$finish;end
endmodule
