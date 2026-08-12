`timescale 1ns/1ps
module tb_full_attack_fault_protection;
  logic clk=0,rst=0;always #5 clk=~clk;
  logic[7:0]aw,ar;logic awv,awr,wv,wr,bv,br,arv,arr,rv,rr;logic[31:0]wd,rd;
  logic[3:0]ws;logic[1:0]bp,rp;logic[5:0]fi;logic fdet;logic[7:0]fcode;
  logic[3:0]qv,qr,qd,sv,sready,sauth,serr;logic[31:0]qlen;logic[255:0]qcount,scount;
  logic[2047:0]qdata,sdata;logic[511:0]qtag,stag;
  byte skb[0:1631],ctb[0:767];integer f,i,n;logic[31:0]status;
  mlkem_secure_channel_fault_protected_axi_top dut(clk,rst,aw,awv,awr,wd,ws,wv,wr,bp,bv,br,
    ar,arv,arr,rd,rp,rv,rr,fi,fdet,fcode,qv,qr,qd,qlen,qcount,qdata,qtag,
    sv,sready,sauth,serr,scount,sdata,stag);
  function automatic[511:0]pack64(input[511:0]x);integer j;begin
    for(j=0;j<64;j=j+1)pack64[8*j+:8]=x[511-8*j-:8];end endfunction
  function automatic[127:0]pack16(input[127:0]x);integer j;begin
    for(j=0;j<16;j=j+1)pack16[8*j+:8]=x[127-8*j-:8];end endfunction
  task automatic reset_dut;begin rst=0;awv=0;wv=0;br=0;arv=0;rr=0;qv=0;qd=0;
    qlen=0;qcount=0;qdata=0;qtag=0;sready=0;fi=0;repeat(4)@(posedge clk);rst=1;repeat(2)@(posedge clk);end endtask
  task automatic write(input[7:0]a,input[31:0]d);begin @(negedge clk);aw=a;wd=d;awv=1;wv=1;br=1;
    while(!(awr&&wr))@(posedge clk);@(negedge clk);awv=0;wv=0;while(!bv)@(posedge clk);@(negedge clk);br=0;end endtask
  task automatic read(input[7:0]a,output[31:0]d);begin @(negedge clk);ar=a;arv=1;rr=1;
    while(!arr)@(posedge clk);@(negedge clk);arv=0;while(!rv)@(posedge clk);#1;d=rd;@(negedge clk);rr=0;end endtask
  task automatic load_vectors(input logic bad_pk,input logic bad_ct);logic[31:0]w;begin
    write(8'h20,0);write(8'h24,0);
    for(i=0;i<408;i=i+1)begin w={skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]};
      if(bad_pk&&i==192)w=w^1;write(8'h28,w);end
    write(8'h20,1);write(8'h24,0);
    for(i=0;i<192;i=i+1)begin w={ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]};
      if(bad_ct&&i==0)w=w^1;write(8'h28,w);end
  end endtask
  task automatic handshake;begin write(8'h0c,0);write(8'h10,32'h01020304);
    write(8'h04,32'h100);write(8'h04,1);wait(dut.final_done);repeat(3)@(posedge clk);read(8'h08,status);end endtask
  task automatic request0(input logic decrypt,input[7:0]len,input[63:0]count,
      input[511:0]data,input[127:0]tag);begin
    qd[0]=decrypt;qlen[7:0]=len;qcount[63:0]=count;qdata[511:0]=data;qtag[127:0]=tag;
    qv[0]=1;wait(qr[0]);@(posedge clk);#1;qv[0]=0;wait(sv[0]);#1;
  end endtask
  task automatic consume0;begin sready[0]=1;@(posedge clk);#1;sready[0]=0;end endtask
  localparam[511:0]PLAIN=512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000;
  localparam[511:0]PC_CT=512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a;
  localparam[127:0]PC_TAG=128'h98fe11b3409dd2e381c7711868916dcf;
  initial begin aw=0;ar=0;wd=0;ws=15;
    f=$fopen("../../golden_reference/secret_key.bin","rb");if(!f)$fatal(1,"sk");n=$fread(skb,f);$fclose(f);
    f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");if(!f)$fatal(1,"ct");n=$fread(ctb,f);$fclose(f);

    reset_dut();load_vectors(0,0);handshake();
    if(!status[2]||status[3]||fdet)$fatal(1,"normal protected handshake");
    $display("PASS normal protected handshake and session install");
    request0(1,40,0,pack64(PC_CT),pack16(PC_TAG));
    if(!sauth[0]||serr[0]||sdata[511:0]!==pack64(PLAIN))$fatal(1,"valid packet");consume0();
    $display("PASS valid authenticated packet");
    request0(1,40,0,pack64(PC_CT),pack16(PC_TAG));
    if(sauth[0]||!serr[0]||sdata[511:0]!==0)$fatal(1,"replay");consume0();
    $display("PASS replayed counter rejected");
    request0(1,40,1,pack64(PC_CT),pack16(PC_TAG)^1);
    if(sauth[0]||!serr[0]||sdata[511:0]!==0)$fatal(1,"bad tag");consume0();
    $display("PASS bad Poly1305 tag rejected fail-closed");
    request0(0,65,0,pack64(PLAIN),0);
    if(sauth[0]||!serr[0])$fatal(1,"oversize");consume0();
    $display("PASS oversized payload rejected");

    reset_dut();load_vectors(0,1);handshake();
    if(!status[2]||!status[3])$fatal(1,"tampered ciphertext accepted");
    request0(0,40,0,pack64(PLAIN),0);if(sauth[0]||!serr[0])$fatal(1,"session installed after bad ct");consume0();
    $display("PASS ML-KEM ciphertext tamper rejected and session not installed");

    reset_dut();load_vectors(1,0);handshake();
    if(!status[2]||!status[3])$fatal(1,"tampered public key accepted");
    $display("PASS embedded public-key tamper rejected by H(pk)");

    reset_dut();load_vectors(0,0);force dut.dec.dec.forward_count=0;handshake();
    release dut.dec.dec.forward_count;
    if(!status[3])$fatal(1,"NTT operation-count fault accepted");
    $display("PASS missing NTT operation detected by operation counter");

    reset_dut();load_vectors(0,0);force dut.dec.enc.compare.mismatch_bar=0;handshake();
    release dut.dec.enc.compare.mismatch_bar;
    if(!status[3])$fatal(1,"ciphertext compare rail fault accepted");
    $display("PASS ciphertext-compare rail fault forces rejection");

    reset_dut();load_vectors(0,0);fi[0]=1;
    fork begin wait(dut.hs_hash);@(posedge clk);#1;fi[0]=0;end begin handshake();end join
    if(!status[3]||!fdet||!(fcode&8'h01))$fatal(1,"hash sequence fault missed %h",fcode);
    $display("PASS shared-hash command fault detected and install blocked");

    reset_dut();load_vectors(0,0);fi[1]=1;handshake();fi[1]=0;
    if(!status[3]||!fdet||!(fcode&8'h04))$fatal(1,"secret storage fault missed %h",fcode);
    request0(0,40,0,pack64(PLAIN),0);if(sauth[0]||!serr[0])$fatal(1,"session installed after fault");consume0();
    $display("PASS shared-secret bit fault detected and session install blocked");

    reset_dut();load_vectors(0,0);fi[2]=1;handshake();fi[2]=0;
    if(!status[3]||!fdet||!(fcode&8'h08))$fatal(1,"transcript storage fault missed %h",fcode);
    $display("PASS transcript-hash bit fault detected and install blocked");

    reset_dut();load_vectors(0,0);fi[3]=1;handshake();fi[3]=0;
    if(!status[3]||!fdet||!(fcode&8'h10))$fatal(1,"KDF material fault missed %h",fcode);
    $display("PASS traffic-key material bit fault detected and install blocked");

    reset_dut();load_vectors(0,0);fi[4]=1;handshake();fi[4]=0;
    if(!status[3]||!fdet||!(fcode&8'h20))$fatal(1,"hash timeout fault missed %h",fcode);
    $display("PASS stalled hash completion detected by watchdog");

    reset_dut();fi[5]=1;@(posedge clk);#1;fi[5]=0;@(posedge clk);#1;
    if(!fdet||!(fcode&8'h40)||sv[0])$fatal(1,"spurious output valid missed %h",fcode);
    $display("PASS spurious output-valid detected and suppressed");
    $display("ALL NETWORK ATTACK AND FAULT-PROTECTION TESTS PASSED");$finish;
  end
  initial begin #300000000;$fatal(1,"full attack timeout state=%0d code=%h",dut.state,fcode);end
endmodule
