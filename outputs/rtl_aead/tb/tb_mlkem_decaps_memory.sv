`timescale 1ns/1ps
module tb_mlkem_decaps_memory;
    logic clk=0,hv,hwe,hrdy,skwe,ctwe,pwe;logic[1:0]region;
    logic[11:0]haddr,paddr;logic[31:0]hw,hr,skw,skr,ctw,ctr;
    logic[8:0]skaddr;logic[7:0]ctaddr;logic[15:0]pw,pr;
    always #5 clk=~clk;
    mlkem_decaps_memory dut(clk,hv,hwe,region,haddr,hw,hr,hrdy,
        skwe,skaddr,skw,skr,ctwe,ctaddr,ctw,ctr,pwe,paddr,pw,pr);
    task automatic host_write(input[1:0]r,input integer a,input[31:0]d);begin
        region=r;haddr=a;hw=d;hv=1;hwe=1;@(posedge clk);#1;hv=0;hwe=0;end endtask
    initial begin hv=0;hwe=0;region=0;haddr=0;hw=0;skwe=0;ctwe=0;pwe=0;
        skaddr=0;ctaddr=0;paddr=0;skw=0;ctw=0;pw=0;repeat(2)@(posedge clk);
        host_write(0,407,32'hdeadbeef);skaddr=407;@(posedge clk);#1;
        if(skr!==32'hdeadbeef)$fatal(1,"SK dual port");
        host_write(1,191,32'h01234567);ctaddr=191;@(posedge clk);#1;
        if(ctr!==32'h01234567)$fatal(1,"CT dual port");
        host_write(2,3071,32'h00000c75);paddr=3071;@(posedge clk);#1;
        if(pr!==16'h0c75)$fatal(1,"poly dual port");
        paddr=9;pwe=1;pw=16'h0608;@(posedge clk);#1;pwe=0;
        region=2;haddr=9;hv=1;hwe=0;@(posedge clk);#1;hv=0;
        if(!hrdy||hr!==32'h00000608)$fatal(1,"host read window");
        $display("ALL ML-KEM DECAPS MEMORY TESTS PASSED");$finish;end
endmodule
