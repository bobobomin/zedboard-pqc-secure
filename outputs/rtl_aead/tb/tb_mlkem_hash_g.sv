`timescale 1ns/1ps
module tb_mlkem_hash_g;logic clk=0,rst=0,start,busy,done;logic[511:0]in,digest,expected;integer i;
    always #5 clk=~clk;mlkem_hash_g dut(clk,rst,start,in,busy,done,digest);
    function automatic[255:0]pack32(input[255:0]x);integer j;begin
        for(j=0;j<32;j=j+1)pack32[8*j+:8]=x[255-8*j-:8];end endfunction
    function automatic[511:0]pack64(input[511:0]x);integer j;begin
        for(j=0;j<64;j=j+1)pack64[8*j+:8]=x[511-8*j-:8];end endfunction
    initial begin start=0;in[255:0]=pack32(256'ha0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf);
        in[511:256]=pack32(256'h82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea);
        expected=pack64(512'hee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f8e2da4aa5b08ceee77d59ac902da2380bd03b5a24f58307365a4243bd1de7f6a);
        repeat(3)@(posedge clk);rst=1;@(posedge clk);start=1;@(posedge clk);#1;start=0;
        wait(done);#1;if(digest!==expected)$fatal(1,"Hash G mismatch");
        $display("ALL ML-KEM HASH-G TESTS PASSED");$finish;end
endmodule
