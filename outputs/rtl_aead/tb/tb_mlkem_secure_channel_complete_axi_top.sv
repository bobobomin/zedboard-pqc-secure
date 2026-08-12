`timescale 1ns/1ps
module tb_mlkem_secure_channel_complete_axi_top;
  logic clk=0,rst=0;always #5 clk=~clk;logic[5:0]fi;logic fdet;logic[7:0]fcode;
  logic[7:0]maw,mar;logic mawv,mawr,mwv,mwr,mbv,mbr,marv,marr,mrv,mrr;
  logic[31:0]mwd,mrd;logic[3:0]mws;logic[1:0]mbp,mrp;
  logic[8:0]aaw,aar;logic aawv,aawr,awv,awr,abv,abr,aarv,aarr,arv,arr;
  logic[31:0]awd,ard;logic[3:0]aws;logic[1:0]abp,arp;
  byte skb[0:1631],ctb[0:767];integer f,i,n;logic[31:0]status,w;
  logic[511:0]got;logic[127:0]got_tag;
  mlkem_secure_channel_complete_axi_top dut(clk,rst,maw,mawv,mawr,mwd,mws,mwv,mwr,mbp,mbv,mbr,
    mar,marv,marr,mrd,mrp,mrv,mrr,aaw,aawv,aawr,awd,aws,awv,awr,abp,abv,abr,
    aar,aarv,aarr,ard,arp,arv,arr,fi,fdet,fcode);
  function automatic[511:0]pack64(input[511:0]x);integer j;begin
    for(j=0;j<64;j=j+1)pack64[8*j+:8]=x[511-8*j-:8];end endfunction
  function automatic[127:0]pack16(input[127:0]x);integer j;begin
    for(j=0;j<16;j=j+1)pack16[8*j+:8]=x[127-8*j-:8];end endfunction
  task automatic mw(input[7:0]x,input[31:0]d);begin @(negedge clk);maw=x;mwd=d;mawv=1;mwv=1;mbr=1;
    while(!(mawr&&mwr))@(posedge clk);@(negedge clk);mawv=0;mwv=0;while(!mbv)@(posedge clk);@(negedge clk);mbr=0;end endtask
  task automatic mr(input[7:0]x,output[31:0]d);begin @(negedge clk);mar=x;marv=1;mrr=1;
    while(!marr)@(posedge clk);@(negedge clk);marv=0;while(!mrv)@(posedge clk);#1;d=mrd;@(negedge clk);mrr=0;end endtask
  task automatic aw(input[8:0]x,input[31:0]d);begin @(negedge clk);aaw=x;awd=d;aawv=1;awv=1;abr=1;
    while(!(aawr&&awr))@(posedge clk);@(negedge clk);aawv=0;awv=0;while(!abv)@(posedge clk);@(negedge clk);abr=0;end endtask
  task automatic ar(input[8:0]x,output[31:0]d);begin @(negedge clk);aar=x;aarv=1;arr=1;
    while(!aarr)@(posedge clk);@(negedge clk);aarv=0;while(!arv)@(posedge clk);#1;d=ard;@(negedge clk);arr=0;end endtask
  task automatic put_data(input[511:0]v);begin for(i=0;i<16;i=i+1)aw(9'h100+4*i,v[32*i+:32]);end endtask
  task automatic put_tag(input[127:0]v);begin for(i=0;i<4;i=i+1)aw(9'h140+4*i,v[32*i+:32]);end endtask
  task automatic get_data(output[511:0]v);begin for(i=0;i<16;i=i+1)begin ar(9'h180+4*i,w);v[32*i+:32]=w;end end endtask
  task automatic get_tag(output[127:0]v);begin for(i=0;i<4;i=i+1)begin ar(9'h1c0+4*i,w);v[32*i+:32]=w;end end endtask
  task automatic wait_packet;begin status=0;while(!status[1])ar(9'h008,status);end endtask
  localparam[511:0]PLAIN=512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000;
  localparam[511:0]ZB_CT=512'hb7b235da3dbbb9ecd92eca9019e9223a368ca0aad5fd167f9c86595d727381cb0ecf98c4fd286c963ffe346c8644bd72386083ca105e9f23cdbc2697877d85fa;
  localparam[127:0]ZB_TAG=128'h0b8552e36371bcd72ab7f0aba138952c;
  localparam[511:0]PC_CT=512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a;
  localparam[127:0]PC_TAG=128'h98fe11b3409dd2e381c7711868916dcf;
  initial begin maw=0;mar=0;mawv=0;mwv=0;mbr=0;marv=0;mrr=0;mwd=0;mws=15;
    aaw=0;aar=0;aawv=0;awv=0;abr=0;aarv=0;arr=0;awd=0;aws=15;fi=0;
    f=$fopen("../../golden_reference/secret_key.bin","rb");if(!f)$fatal(1,"sk");n=$fread(skb,f);$fclose(f);
    f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");if(!f)$fatal(1,"ct");n=$fread(ctb,f);$fclose(f);
    repeat(4)@(posedge clk);rst=1;repeat(2)@(posedge clk);
    mw(8'h20,0);mw(8'h24,0);for(i=0;i<408;i=i+1)mw(8'h28,{skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]});
    mw(8'h20,1);mw(8'h24,0);for(i=0;i<192;i=i+1)mw(8'h28,{ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]});
    mw(8'h0c,0);mw(8'h10,32'h01020304);mw(8'h04,32'h100);mw(8'h04,1);
    wait(dut.core.final_done);repeat(3)@(posedge clk);mr(8'h08,status);
    if(!status[2]||status[3]||fdet)$fatal(1,"protected Decaps failed %h",status);
    $display("PASS dual-AXI ML-KEM load, Decaps and atomic session install");
    aw(9'h00c,0);aw(9'h010,40);put_data(pack64(PLAIN));aw(9'h004,1);wait_packet();
    if(!status[2]||status[3])$fatal(1,"encrypt status %h",status);get_data(got);
    if(got!==pack64(ZB_CT))$fatal(1,"encrypt data");get_tag(got_tag);
    if(got_tag!==pack16(ZB_TAG))$fatal(1,"encrypt tag");
    $display("PASS PS-facing AXI traffic encryption uses installed ZB-to-PC session");
    aw(9'h004,32'h100);aw(9'h014,0);aw(9'h018,0);put_data(pack64(PC_CT));put_tag(pack16(PC_TAG));
    aw(9'h004,3);wait_packet();if(!status[2]||status[3])$fatal(1,"decrypt status %h",status);get_data(got);
    if(got!==pack64(PLAIN))$fatal(1,"decrypt data");
    $display("PASS PS-facing AXI traffic authenticated decryption");
    aw(9'h004,32'h100);aw(9'h004,3);wait_packet();if(status[2]||!status[3])$fatal(1,"replay status %h",status);
    get_data(got);if(got!==0)$fatal(1,"replay plaintext leak");
    $display("PASS PS-facing AXI replay rejection remains fail-closed");
    $display("ALL COMPLETE DUAL-AXI SECURE CHANNEL TESTS PASSED");$finish;
  end
  initial begin #300000000;$fatal(1,"complete AXI timeout");end
endmodule
