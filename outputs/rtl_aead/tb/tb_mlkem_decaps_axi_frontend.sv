`timescale 1ns/1ps
module tb_mlkem_decaps_axi_frontend;
    logic clk=0,rst=0;always #5 clk=~clk;logic[7:0]aw,ar;logic awv,awr,wv,wr,bv,br,arv,arr,rv,rr;
    logic[31:0]wd,rd,sid,skrd,ctrd;logic[3:0]ws;logic[1:0]bp,rp,slot;logic start,busy=0,done=0,fail=0;
    logic skwe=0,ctwe=0,pwe=0;logic[8:0]ska=0;logic[7:0]cta=0;logic[11:0]pa=0;
    logic[31:0]skwd=0,ctwd=0;logic[15:0]pwd=0,prd;
    mlkem_decaps_axi_lite_frontend dut(clk,rst,aw,awv,awr,wd,ws,wv,wr,bp,bv,br,
        ar,arv,arr,rd,rp,rv,rr,start,slot,sid,busy,done,fail,
        skwe,ska,skwd,skrd,ctwe,cta,ctwd,ctrd,pwe,pa,pwd,prd);
    task automatic write(input[7:0]a,input[31:0]d);begin @(negedge clk);aw=a;wd=d;awv=1;wv=1;br=1;
        while(!(awr&&wr))@(posedge clk);@(negedge clk);awv=0;wv=0;while(!bv)@(posedge clk);
        @(negedge clk);br=0;end endtask
    task automatic read(input[7:0]a,output[31:0]d);begin @(negedge clk);ar=a;arv=1;rr=1;
        while(!arr)@(posedge clk);@(negedge clk);arv=0;while(!rv)@(posedge clk);#1;d=rd;
        @(negedge clk);rr=0;end endtask
    logic[31:0]x;
    initial begin aw=0;ar=0;awv=0;wv=0;br=0;arv=0;rr=0;wd=0;ws=15;
        repeat(4)@(posedge clk);rst=1;repeat(2)@(posedge clk);
        write(32,0);write(36,407);write(40,32'hdeadbeef);ska=407;@(posedge clk);#1;
        if(skrd!==32'hdeadbeef)$fatal(1,"AXI SK window");
        write(32,1);write(36,191);write(40,32'h01234567);cta=191;@(posedge clk);#1;
        if(ctrd!==32'h01234567)$fatal(1,"AXI CT window");
        write(12,2);write(16,32'h01020304);write(4,1);@(posedge clk);#1;
        if(slot!==2||sid!==32'h01020304)$fatal(1,"control registers");
        $display("ALL ML-KEM DECAPS AXI FRONTEND TESTS PASSED");$finish;end
endmodule
