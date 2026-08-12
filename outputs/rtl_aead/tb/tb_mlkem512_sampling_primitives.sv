`timescale 1ns/1ps
module tb_mlkem512_sampling_primitives;
    logic[31:0]e2in;logic signed[127:0]e2;logic[23:0]e3in,rjin;logic signed[63:0]e3;
    logic[11:0]v0,v1;logic ok0,ok1;logic signed[15:0]a,b;logic sub;logic[15:0]sum;
    mlkem_cbd_eta2_group x(e2in,e2);mlkem_cbd_eta3_group y(e3in,e3);
    mlkem_rejection_pair z(rjin,v0,ok0,v1,ok1);mlkem_coeff_addsub q(a,b,sub,sum);
    task automatic ck2(input integer n,input integer exp);begin
        if($signed(e2[16*n+:16])!=exp)$fatal(1,"eta2[%0d]",n);end endtask
    task automatic ck3(input integer n,input integer exp);begin
        if($signed(e3[16*n+:16])!=exp)$fatal(1,"eta3[%0d]",n);end endtask
    initial begin e2in=32'h12345678;e3in=24'habcdef;rjin=24'habcdef;a=100;b=-200;sub=0;#1;
        ck2(0,-1);ck2(1,1);ck2(2,0);ck2(3,0);ck2(4,-1);ck2(5,2);ck2(6,1);ck2(7,1);
        ck3(0,1);ck3(1,1);ck3(2,-2);ck3(3,-1);
        if(v0!=3567||ok0||v1!=2748||!ok1)$fatal(1,"rejection pair");
        if(sum!=3229)$fatal(1,"canonical add");sub=1;#1;if(sum!=300)$fatal(1,"canonical sub");
        $display("ALL ML-KEM-512 SAMPLING PRIMITIVE TESTS PASSED");$finish;end
endmodule
