`timescale 1ns/1ps
module tb_mlkem_secure_channel_shared_axi_top;
    logic clk=0,rst=0;always #5 clk=~clk;logic[7:0]aw,ar;logic awv,awr,wv,wr,bv,br,arv,arr,rv,rr;
    logic[31:0]wd,rd;logic[3:0]ws;logic[1:0]bp,rp;
    logic[3:0]qv,qr,qd,sv,sready,sauth,serr;logic[31:0]qlen;logic[255:0]qcount,scount;
    logic[2047:0]qdata,sdata;logic[511:0]qtag,stag;byte skb[0:1631],ctb[0:767];integer f,i,n;
    mlkem_secure_channel_shared_axi_top dut(clk,rst,aw,awv,awr,wd,ws,wv,wr,bp,bv,br,
        ar,arv,arr,rd,rp,rv,rr,qv,qr,qd,qlen,qcount,qdata,qtag,sv,sready,sauth,serr,scount,sdata,stag);
    function automatic[511:0]pack64(input[511:0]x);integer j;begin
        for(j=0;j<64;j=j+1)pack64[8*j+:8]=x[511-8*j-:8];end endfunction
    function automatic[127:0]pack16(input[127:0]x);integer j;begin
        for(j=0;j<16;j=j+1)pack16[8*j+:8]=x[127-8*j-:8];end endfunction
    task automatic write(input[7:0]a,input[31:0]d);begin @(negedge clk);aw=a;wd=d;awv=1;wv=1;br=1;
        while(!(awr&&wr))@(posedge clk);@(negedge clk);awv=0;wv=0;while(!bv)@(posedge clk);@(negedge clk);br=0;end endtask
    task automatic read(input[7:0]a,output[31:0]d);begin @(negedge clk);ar=a;arv=1;rr=1;
        while(!arr)@(posedge clk);@(negedge clk);arv=0;while(!rv)@(posedge clk);#1;d=rd;@(negedge clk);rr=0;end endtask
    logic[31:0]status;
    initial begin aw=0;ar=0;awv=0;wv=0;br=0;arv=0;rr=0;wd=0;ws=15;
        qv=0;qd=0;qlen=0;qcount=0;qdata=0;qtag=0;sready=0;
        f=$fopen("../../golden_reference/secret_key.bin","rb");n=$fread(skb,f);$fclose(f);
        f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");n=$fread(ctb,f);$fclose(f);
        repeat(4)@(posedge clk);rst=1;repeat(2)@(posedge clk);
        write(8'h20,0);write(8'h24,0);
        for(i=0;i<408;i=i+1)write(8'h28,{skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]});
        write(8'h20,1);write(8'h24,0);
        for(i=0;i<192;i=i+1)write(8'h28,{ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]});
        write(8'h0c,0);write(8'h10,32'h01020304);write(8'h04,32'h100);write(8'h04,1);
        wait(dut.final_done);repeat(3)@(posedge clk);read(8'h08,status);
        if(!status[2]||status[3])$fatal(1,"shared AXI Decaps/session status %h",status);
        qlen[7:0]=40;qdata[511:0]=pack64(512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000);
        qv[0]=1;wait(qr[0]);@(posedge clk);#1;qv[0]=0;wait(sv[0]);#1;
        if(!sauth[0]||serr[0]||sdata[511:0]!==pack64(512'hb7b235da3dbbb9ecd92eca9019e9223a368ca0aad5fd167f9c86595d727381cb0ecf98c4fd286c963ffe346c8644bd72386083ca105e9f23cdbc2697877d85fa)
          ||stag[127:0]!==pack16(128'h0b8552e36371bcd72ab7f0aba138952c))$fatal(1,"shared automatic AEAD slot install");
        $display("ALL SHARED-KECCAK AXI-LITE TO AEAD SESSION TESTS PASSED");$finish;
    end
    initial begin #100000000;$fatal(1,"shared AXI secure channel timeout state=%0d",dut.state);end
endmodule
