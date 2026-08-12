`timescale 1ns/1ps
module tb_mlkem512_decaps_aux;
    logic clk=0,rst=0;always #5 clk=~clk;
    logic[31:0]skmem[0:407],ctmem[0:191];logic[15:0]pmem[0:3071];
    byte skb[0:1631],ctb[0:767];
    logic[8:0]ska;logic[7:0]cta;logic[11:0]pa;logic[31:0]skr,ctr;logic[15:0]pr;
    always_ff @(posedge clk)begin skr<=skmem[ska];ctr<=ctmem[cta];pr<=pmem[pa];end
    logic us,ud,uwe;logic[8:0]uska;logic[11:0]upa;logic[15:0]upd;logic[255:0]rho,hpk,z;
    mlkem512_unpack_public_controller up(clk,rst,us,,ud,uska,skr,uwe,upa,upd,rho,hpk,z);
    logic hs,hd;logic[8:0]hska;logic[255:0]hcalc;
    mlkem512_public_key_hash ph(clk,rst,hs,,hd,hcalc,hska,skr);
    logic js,jd;logic[7:0]jcta;logic[255:0]jcalc;
    mlkem512_rejection_hash jh(clk,rst,js,z,,jd,jcalc,jcta,ctr);
    logic xs,xd,xwe;logic[7:0]xcta;logic[8:0]xska;logic[11:0]xpa;logic[15:0]xpd;
    mlkem512_unpack_controller xu(clk,rst,xs,,xd,xcta,ctr,xska,skr,xwe,xpa,xpd);
    logic cs,cd,cmode,cclear,mis;logic[3:0]cslot;logic[9:0]cbase;logic[11:0]cpa;logic[7:0]ccta;
    mlkem512_pack_compare_controller pc(clk,rst,cs,cclear,cmode,cslot,cbase,,cd,mis,cpa,pr,ccta,ctr);
    logic ms,md,mwe;logic[11:0]mpa;logic[15:0]mpd;
    mlkem_poly_frommsg_controller fm(clk,rst,ms,256'ha0,4'd7,,md,mwe,mpa,mpd);
    integer f,i,owner;
    always_comb begin
        case(owner)0:begin ska=uska;cta=0;pa=upa;end
            1:begin ska=hska;cta=0;pa=0;end
            2:begin ska=0;cta=jcta;pa=0;end
            3:begin ska=xska;cta=xcta;pa=xpa;end
            4:begin ska=0;cta=ccta;pa=cpa;end
            default:begin ska=0;cta=0;pa=mpa;end endcase
    end
    always_ff @(posedge clk)begin if(uwe)pmem[upa]<=upd;if(xwe)pmem[xpa]<=xpd;if(mwe)pmem[mpa]<=mpd;end
    task automatic pulse(ref logic s);begin s=1;@(posedge clk);#1;s=0;end endtask
    initial begin
        f=$fopen("../../golden_reference/secret_key.bin","rb");if(f==0)$fatal(1,"sk open");
        if($fread(skb,f)!=1632)$fatal(1,"sk read");$fclose(f);
        f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");if(f==0)$fatal(1,"ct open");
        if($fread(ctb,f)!=768)$fatal(1,"ct read");$fclose(f);
        for(i=0;i<408;i=i+1)skmem[i]={skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]};
        for(i=0;i<192;i=i+1)ctmem[i]={ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]};
        us=0;hs=0;js=0;xs=0;cs=0;ms=0;cclear=0;cmode=0;cslot=0;cbase=0;owner=0;
        repeat(3)@(posedge clk);rst=1;@(posedge clk);
        pulse(us);wait(ud);#1;$display("PASS public unpack");
        if(rho!==256'h6cb2636d1b5a069ac53b1cb8e0edd1eb7c30058f998fc437c5d8f800d0ad4b34)
            begin $display("rho=%h",rho);$fatal(1,"rho");end
        if(hpk!==256'hea5a366f0e0efa0e15dedaea2f0ca555f655745b6cbbe276b3638064ff01f182)$fatal(1,"hpk");
        if(z!==256'h3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120)$fatal(1,"z");
        if(pmem[0]!=1337||pmem[1]!=2073||pmem[510]!=1862||pmem[511]!=567)$fatal(1,"pk decode");
        owner=1;hs=1;@(posedge clk);#1;hs=0;wait(hd);#1;$display("PASS public hash");if(hcalc!==hpk)$fatal(1,"pk hash");
        owner=2;js=1;@(posedge clk);#1;js=0;wait(jd);#1;$display("PASS rejection hash");
        if(jcalc!==256'ha8b69f0b8e995efb5a84f0fecd0833b75cdb1c54c6c452b3a8263d5321624bf6)$fatal(1,"J");
        owner=3;xs=1;@(posedge clk);#1;xs=0;wait(xd);#1;$display("PASS ciphertext unpack");
        owner=4;
        cclear=1;cmode=0;cslot=0;cbase=0;pulse(cs);cclear=0;wait(cd);@(posedge clk);#1;$display("PASS compare b0");
        cslot=1;cbase=320;pulse(cs);wait(cd);@(posedge clk);#1;$display("PASS compare b1");
        cmode=1;cslot=2;cbase=640;pulse(cs);wait(cd);@(posedge clk);#1;$display("PASS compare v");
        if(mis)$fatal(1,"pack compare roundtrip");
        owner=5;pulse(ms);wait(md);#1;if(pmem[7*256+5]!=1665||pmem[7*256+6]!=0||pmem[7*256+7]!=1665)$fatal(1,"frommsg");
        $display("ALL ML-KEM-512 DECAPS AUXILIARY TESTS PASSED");$finish;
    end
    initial begin #5000000;$fatal(1,"aux timeout owner=%0d",owner);end
endmodule
