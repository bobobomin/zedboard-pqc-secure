`timescale 1ns/1ps
module tb_mlkem_poly_bridge_controller;
    logic clk=0,rst=0,hv,hwe,hrdy,start,busy,done,pwe;logic[1:0]region=2,cmd;
    logic[11:0]ha,pa;logic[31:0]hw,hr;logic[15:0]pw,pr;logic[3:0]sa,sb,sd;integer i;
    always #5 clk=~clk;
    mlkem_decaps_memory mem(clk,hv,hwe,region,ha,hw,hr,hrdy,
        1'b0,9'd0,32'd0,,1'b0,8'd0,32'd0,,pwe,pa,pw,pr);
    mlkem_poly_bridge_controller dut(clk,rst,start,cmd,sa,sb,sd,busy,done,pwe,pa,pw,pr);
    task automatic wr(input integer a,input integer d);begin ha=a;hw=d;hv=1;hwe=1;
        @(posedge clk);#1;hv=0;hwe=0;end endtask
    task automatic ck(input integer a,input integer e);begin ha=a;hv=1;hwe=0;
        @(posedge clk);#1;hv=0;if(hr[15:0]!==e[15:0])$fatal(1,"bridge[%0d]",a);end endtask
    initial begin hv=0;hwe=0;ha=0;hw=0;start=0;cmd=0;sa=0;sb=1;sd=5;
        repeat(3)@(posedge clk);rst=1;@(posedge clk);
        for(i=0;i<256;i=i+1)wr(i,(i*17+3)%3329);
        start=1;@(posedge clk);#1;start=0;wait(done);@(posedge clk);#1;
        ck(5*256+0,-736);ck(5*256+1,-3651);ck(5*256+127,-3023);ck(5*256+255,4619);
        $display("ALL ML-KEM POLYNOMIAL BRIDGE TESTS PASSED");$finish;end
endmodule
