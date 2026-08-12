`timescale 1ns/1ps
module tb_mlkem_noise_poly_generator;logic clk=0,rst=0,start,eta,busy,done,we;logic[255:0]seed;
    logic[7:0]nonce;logic[11:0]addr;logic[15:0]data;logic signed[15:0]poly[0:255];integer i;
    always #5 clk=~clk;always_ff @(posedge clk)if(we)poly[addr]<=data;
    function automatic[255:0]pack32(input[255:0]x);integer j;begin
        for(j=0;j<32;j=j+1)pack32[8*j+:8]=x[255-8*j-:8];end endfunction
    mlkem_noise_poly_generator dut(clk,rst,start,seed,nonce,eta,4'd0,
        busy,done,we,addr,data);
    initial begin start=0;eta=1;nonce=0;seed=pack32(256'h8e2da4aa5b08ceee77d59ac902da2380bd03b5a24f58307365a4243bd1de7f6a);
        repeat(3)@(posedge clk);rst=1;@(posedge clk);start=1;@(posedge clk);#1;start=0;wait(done);#1;
        if(poly[0]!=1||poly[1]!=-1||poly[2]!=-1||poly[3]!=0||poly[4]!=0||poly[5]!=-1||poly[6]!=2||poly[7]!=0)$fatal(1,"eta3");
        @(posedge clk);eta=0;nonce=2;start=1;@(posedge clk);#1;start=0;wait(done);#1;
        if(poly[0]!=0||poly[1]!=-1||poly[2]!=-1||poly[3]!=0||poly[4]!=0||poly[5]!=0||poly[6]!=1||poly[7]!=-1)$fatal(1,"eta2");
        $display("ALL ML-KEM NOISE GENERATOR TESTS PASSED");$finish;end
endmodule
