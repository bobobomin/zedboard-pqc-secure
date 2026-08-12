`timescale 1ns/1ps
module tb_mlkem_shared_hash_engine;
    logic clk=0,rst=0,start,done,err,pwe,eta;logic[2:0]cmd;logic[255:0]d0,d1;
    logic[31:0]sid;logic[7:0]x,y,nonce,cta;logic[3:0]slot;logic[8:0]ska;
    logic[11:0]pa;logic[15:0]pd;logic[31:0]skr,ctr;logic[575:0]digest;
    logic[31:0]skm[0:407],ctm[0:191];logic signed[15:0]poly[0:3071];
    byte skb[0:1631],ctb[0:767];integer f,i,n;
    always #5 clk=~clk;always_ff @(posedge clk)begin skr<=skm[ska];ctr<=ctm[cta];if(pwe)poly[pa]<=pd;end
    mlkem_shared_hash_engine dut(clk,rst,start,cmd,d0,d1,sid,x,y,nonce,eta,slot,
        ,done,err,digest,ska,skr,cta,ctr,pwe,pa,pd);
    function automatic[255:0]pack32(input[255:0]v);integer j;begin
        for(j=0;j<32;j=j+1)pack32[8*j+:8]=v[255-8*j-:8];end endfunction
    task automatic run(input[2:0]c);begin cmd=c;start=1;@(posedge clk);#1;start=0;
        wait(done);@(posedge clk);#1;end endtask
    initial begin start=0;cmd=0;d0=0;d1=0;sid=32'h01020304;x=0;y=0;nonce=0;eta=0;slot=0;
        f=$fopen("../../golden_reference/secret_key.bin","rb");n=$fread(skb,f);$fclose(f);
        f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");n=$fread(ctb,f);$fclose(f);
        for(i=0;i<408;i=i+1)skm[i]={skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]};
        for(i=0;i<192;i=i+1)ctm[i]={ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]};
        repeat(3)@(posedge clk);rst=1;@(posedge clk);
        run(0);$display("PASS shared HPK");if(digest[255:0]!==pack32(256'h82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea))$fatal(1,"HPK");
        d0=pack32(256'ha0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf);
        d1=pack32(256'h82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea);run(1);$display("PASS shared G");
        if(digest[255:0]!==pack32(256'hee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f)||
          digest[511:256]!==pack32(256'h8e2da4aa5b08ceee77d59ac902da2380bd03b5a24f58307365a4243bd1de7f6a))$fatal(1,"G");
        d0=pack32(256'h202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f);run(2);$display("PASS shared J");
        if(digest[255:0]!==pack32(256'hf64b6221533d26a8b352c4c6541cdb5cb73308cdfef0845afb5e998e0b9fb6a8))$fatal(1,"J");
        d0=pack32(256'h344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c);slot=0;x=0;y=0;run(3);$display("PASS shared matrix");
        if(err||poly[0]!=55||poly[1]!=1049||poly[2]!=656||poly[7]!=174)$fatal(1,"matrix");
        d0=pack32(256'h8e2da4aa5b08ceee77d59ac902da2380bd03b5a24f58307365a4243bd1de7f6a);
        slot=1;nonce=0;eta=1;run(4);$display("PASS shared noise");if(poly[256]!=1||poly[257]!=-1||poly[262]!=2)$fatal(1,"noise");
        run(5);$display("PASS shared transcript");if(digest[255:0]!==pack32(256'h0b727acdecaa849e1824e3b9fb450e7db285a4951bf324be08b2d941774d98b0))$fatal(1,"transcript");
        d0=pack32(256'hee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f);
        d1=pack32(256'h0b727acdecaa849e1824e3b9fb450e7db285a4951bf324be08b2d941774d98b0);run(6);
        if(digest[255:0]!==pack32(256'h71732bdafb22b7dcc949f0902c5ef420c16a945633dc87e579fe9e5b7755114a)||
          digest[287:256]!==32'h4ce83f7d||digest[543:288]!==pack32(256'ha814fc7382a5f27c46909f915772cbf64b5c247c32b443c83bc2b328ef94de96)||
          digest[575:544]!==32'haa022ea7)$fatal(1,"KDF");
        $display("ALL SHARED ML-KEM HASH ENGINE TESTS PASSED");$finish;
    end
    initial begin #10000000;$fatal(1,"shared hash timeout cmd=%0d",cmd);end
endmodule
