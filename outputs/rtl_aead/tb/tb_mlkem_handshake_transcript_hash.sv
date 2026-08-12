`timescale 1ns/1ps
module tb_mlkem_handshake_transcript_hash;
    logic clk=0,rst=0,start,done;logic[8:0]ska;logic[7:0]cta;logic[31:0]skr,ctr;
    logic[31:0]skm[0:407],ctm[0:191];byte skb[0:1631],ctb[0:767];logic[255:0]digest;integer f,i,n;
    always #5 clk=~clk;always_ff @(posedge clk)begin skr<=skm[ska];ctr<=ctm[cta];end
    mlkem_handshake_transcript_hash dut(clk,rst,start,32'h01020304,,done,digest,ska,skr,cta,ctr);
    initial begin start=0;f=$fopen("../../golden_reference/secret_key.bin","rb");n=$fread(skb,f);$fclose(f);
        f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");n=$fread(ctb,f);$fclose(f);
        for(i=0;i<408;i=i+1)skm[i]={skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]};
        for(i=0;i<192;i=i+1)ctm[i]={ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]};
        repeat(3)@(posedge clk);rst=1;@(posedge clk);start=1;@(posedge clk);#1;start=0;wait(done);#1;
        if(digest!==256'hb0984d7741d9b208be24f31b95a485b27d0e45fbb9e324189e84aaeccd7a720b)$fatal(1,"transcript");
        $display("ALL ML-KEM TRANSCRIPT HASH TESTS PASSED");$finish;end
endmodule
