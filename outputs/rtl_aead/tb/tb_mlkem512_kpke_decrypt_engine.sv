`timescale 1ns/1ps
module tb_mlkem512_kpke_decrypt_engine;
    logic clk=0,rst=0,start,busy,done,hv,hwe,hrdy,pwe;logic[1:0]region;
    logic[11:0]ha,pa;logic[31:0]hw,hr,skr,ctr;logic[15:0]pw,pr;logic[8:0]ska;
    logic[7:0]cta;logic[255:0]message;byte ctb[0:767],skb[0:1631];integer f,i,n;
    always #5 clk=~clk;
    mlkem_decaps_memory mem(.clk_i(clk),.host_valid_i(hv),.host_we_i(hwe),
        .host_region_i(region),.host_addr_i(ha),.host_wdata_i(hw),
        .host_rdata_o(hr),.host_ready_o(hrdy),.sk_we_i(1'b0),.sk_addr_i(ska),
        .sk_wdata_i(32'd0),.sk_rdata_o(skr),.ct_we_i(1'b0),.ct_addr_i(cta),
        .ct_wdata_i(32'd0),.ct_rdata_o(ctr),.poly_we_i(pwe),.poly_addr_i(pa),
        .poly_wdata_i(pw),.poly_rdata_o(pr));
    mlkem512_kpke_decrypt_engine dut(.clk_i(clk),.rst_ni(rst),.start_i(start),
        .busy_o(busy),.done_o(done),.message_o(message),.ct_addr_o(cta),
        .ct_rdata_i(ctr),.sk_addr_o(ska),.sk_rdata_i(skr),.poly_we_o(pwe),
        .poly_addr_o(pa),.poly_wdata_o(pw),.poly_rdata_i(pr));
    task automatic wr(input[1:0]r,input integer a,input[31:0]d);begin
        region=r;ha=a;hw=d;hv=1;hwe=1;@(posedge clk);#1;hv=0;hwe=0;end endtask
    initial begin hv=0;hwe=0;region=0;ha=0;hw=0;start=0;
        f=$fopen("../../golden_reference/kem_ciphertext.bin","rb");
        if(!f)$fatal(1,"open ciphertext");n=$fread(ctb,f);$fclose(f);
        f=$fopen("../../golden_reference/secret_key.bin","rb");
        if(!f)$fatal(1,"open secret key");n=$fread(skb,f);$fclose(f);
        repeat(3)@(posedge clk);rst=1;@(posedge clk);
        for(i=0;i<192;i=i+1)wr(1,i,{ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]});
        for(i=0;i<408;i=i+1)wr(0,i,{skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]});
        start=1;@(posedge clk);#1;start=0;wait(done);#1;
        for(i=0;i<32;i=i+1)if(message[8*i+:8]!==8'ha0+i)
            $fatal(1,"K-PKE recovered message byte %0d got %02x",i,message[8*i+:8]);
        $display("ALL ML-KEM-512 K-PKE DECRYPT TESTS PASSED");$finish;end
endmodule
