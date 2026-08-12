`timescale 1ns/1ps
module tb_mlkem512_unpack_controller;
    logic clk=0,rst_n=0,start,busy,done,pwe;logic[7:0]cta;logic[8:0]ska;
    logic[31:0]ctw,skw;logic[11:0]pa;logic[15:0]pd;
    logic[31:0]ctmem[0:191],skmem[0:407];logic[15:0]poly[0:1279];integer i;
    always #5 clk=~clk;
    always_ff @(posedge clk)begin ctw<=ctmem[cta];skw<=skmem[ska];if(pwe)poly[pa]<=pd;end
    mlkem512_unpack_controller dut(clk,rst_n,start,busy,done,cta,ctw,ska,skw,pwe,pa,pd);
    initial begin
        for(i=0;i<192;i=i+1)ctmem[i]=0;for(i=0;i<408;i=i+1)skmem[i]=0;
        ctmem[0]=32'h0a876fd5;ctmem[1]=32'h36dad087;ctmem[2]=32'hf320a1e7;
        ctmem[160]=32'h9ad1e337;ctmem[161]=32'h2669838a;
        skmem[0]=32'hd44f5570;skmem[1]=32'h274f3436;skmem[2]=32'hb1852744;
        start=0;repeat(3)@(posedge clk);rst_n=1;@(posedge clk);start=1;
        @(posedge clk);#1;start=0;wait(done);@(posedge clk);#1;
        if(poly[0]!==3189||poly[1]!==1544||poly[2]!==546||poly[3]!==1756)
            $fatal(1,"d10 unpack first group");
        if(poly[4]!==2341||poly[5]!==1424||poly[6]!==2038||poly[7]!==2103)
            $fatal(1,"d10 unpack second group");
        if(poly[512]!==1456||poly[513]!==624||poly[514]!==624||poly[515]!==2913)
            $fatal(1,"d4 unpack");
        if(poly[768]!==1392||poly[769]!==1269||poly[770]!==1748||poly[771]!==835)
            $fatal(1,"secret-key decode12");
        $display("ALL ML-KEM-512 UNPACK CONTROLLER TESTS PASSED");$finish;end
endmodule
