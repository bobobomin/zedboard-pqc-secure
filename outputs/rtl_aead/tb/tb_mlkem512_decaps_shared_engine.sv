`timescale 1ns/1ps
module tb_mlkem512_decaps_shared_engine;
    logic clk=0,rst=0,hv,hwe,hrdy,pwe,swe,cwe,start,busy,done,fail;
    logic[1:0]region;logic[11:0]ha,pa,dpa,hpa;logic[8:0]ska,dska,hska;
    logic[7:0]cta,dcta,hcta;logic[31:0]hw,hr,skr,ctr,swd,cwd;logic[15:0]pw,pr,dpd,hpd;
    logic[255:0]ss,hd0,hd1;logic hs,hbusy,hdone,herr,hpwe,dpwe,heta;
    logic[2:0]hcmd;logic[7:0]hx,hy,hnonce;logic[3:0]hslot;logic[575:0]hdigest;
    byte skb[0:1631],ctb[0:767];integer f,i,n;
    always #5 clk=~clk;
    mlkem_decaps_memory mem(clk,hv,hwe,region,ha,hw,hr,hrdy,swe,ska,swd,skr,
        cwe,cta,cwd,ctr,pwe,pa,pw,pr);
    mlkem512_decaps_shared_engine dec(clk,rst,start,busy,done,fail,ss,
        hs,hcmd,hd0,hd1,hx,hy,hnonce,heta,hslot,hdone,herr,hdigest,
        swe,dska,swd,skr,cwe,dcta,cwd,ctr,dpwe,dpa,dpd,pr);
    mlkem_shared_hash_engine hash(clk,rst,hs,hcmd,hd0,hd1,0,hx,hy,hnonce,heta,hslot,
        hbusy,hdone,herr,hdigest,hska,skr,hcta,ctr,hpwe,hpa,hpd);
    always_comb begin ska=hbusy?hska:dska;cta=hbusy?hcta:dcta;
        pwe=hpwe|dpwe;pa=hpwe?hpa:dpa;pw=hpwe?hpd:dpd;end
    task automatic wr(input[1:0]r,input integer a,input[31:0]d);begin region=r;ha=a;hw=d;
        hv=1;hwe=1;@(posedge clk);#1;hv=0;hwe=0;end endtask
    task automatic run;begin start=1;@(posedge clk);#1;start=0;wait(done);#1;end endtask
    initial begin hv=0;hwe=0;region=0;ha=0;hw=0;start=0;
        f=$fopen("../../golden_reference/secret_key.bin","rb");if(!f)$fatal(1,"sk");n=$fread(skb,f);$fclose(f);
        f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");if(!f)$fatal(1,"ct");n=$fread(ctb,f);$fclose(f);
        repeat(3)@(posedge clk);rst=1;@(posedge clk);
        for(i=0;i<408;i=i+1)wr(0,i,{skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]});
        for(i=0;i<192;i=i+1)wr(1,i,{ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]});
        run();if(fail)$fatal(1,"valid ct rejected");
        if(ss!==256'h4fee9d793a3676384642bf044196602dad235cf6e1044593a5156ffb908f5fee)$fatal(1,"valid ss %h",ss);
        @(posedge clk);wr(1,0,{ctb[3],ctb[2],ctb[1],ctb[0]^8'h01});run();
        if(!fail)$fatal(1,"tampered ct accepted");
        if(ss!==256'hf90958e4ee9df57cfb428a40559b3ed140b80b70d004d67a00ef0a10c999470a)$fatal(1,"rejection ss %h",ss);
        $display("ALL SHARED-KECCAK ML-KEM-512 DECAPS TESTS PASSED");$finish;
    end
    initial begin #50000000;$fatal(1,"shared decaps timeout state=%0d",dec.state);end
endmodule
