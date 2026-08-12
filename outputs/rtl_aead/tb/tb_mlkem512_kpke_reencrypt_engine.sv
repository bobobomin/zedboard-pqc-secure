`timescale 1ns/1ps
module tb_mlkem512_kpke_reencrypt_engine;
    logic clk=0,rst=0,hv,hwe,hrdy,pwe;logic[1:0]region;logic[11:0]ha,pa;
    logic[31:0]hw,hr,skr,ctr;logic[15:0]pw,pr;logic[8:0]ska;logic[7:0]cta;
    byte skb[0:1631],ctb[0:767];integer f,i,n,owner;
    always #5 clk=~clk;
    mlkem_decaps_memory mem(clk,hv,hwe,region,ha,hw,hr,hrdy,1'b0,ska,32'd0,skr,
        1'b0,cta,32'd0,ctr,pwe,pa,pw,pr);
    logic us,ud,uwe;logic[8:0]uska;logic[11:0]upa;logic[15:0]upd;logic[255:0]rho,hpk,z;
    mlkem512_unpack_public_controller up(clk,rst,us,,ud,uska,skr,uwe,upa,upd,rho,hpk,z);
    logic es,ed,emis,ewe;logic[7:0]ecta;logic[11:0]epa;logic[15:0]epd;
    logic[255:0]msg,coins;
    mlkem512_kpke_reencrypt_engine dut(clk,rst,es,msg,rho,coins,,ed,emis,ecta,ctr,ewe,epa,epd,pr);
    always_comb begin ska=uska;cta=ecta;if(owner==0)begin pwe=uwe;pa=upa;pw=upd;end
        else begin pwe=ewe;pa=epa;pw=epd;end end
    task automatic wr(input[1:0]r,input integer a,input[31:0]d);begin region=r;ha=a;hw=d;
        hv=1;hwe=1;@(posedge clk);#1;hv=0;hwe=0;end endtask
    initial begin hv=0;hwe=0;region=0;ha=0;hw=0;us=0;es=0;owner=0;
        for(i=0;i<32;i=i+1)msg[8*i+:8]=8'ha0+i;
        coins=256'h6a7fded13b24a4657330584fa2b503bd8023da02c99ad577eece085baaa42d8e;
        f=$fopen("../../golden_reference/secret_key.bin","rb");if(!f)$fatal(1,"sk");n=$fread(skb,f);$fclose(f);
        f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");if(!f)$fatal(1,"ct");n=$fread(ctb,f);$fclose(f);
        repeat(3)@(posedge clk);rst=1;@(posedge clk);
        for(i=0;i<408;i=i+1)wr(0,i,{skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]});
        for(i=0;i<192;i=i+1)wr(1,i,{ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]});
        us=1;@(posedge clk);#1;us=0;wait(ud);@(posedge clk);#1;owner=1;
        es=1;@(posedge clk);#1;es=0;wait(ed);#1;
        if(emis)$fatal(1,"valid ciphertext did not re-encrypt identically");
        $display("ALL ML-KEM-512 K-PKE RE-ENCRYPT TESTS PASSED");$finish;
    end
    initial begin #20000000;$fatal(1,"reencrypt timeout");end
endmodule
