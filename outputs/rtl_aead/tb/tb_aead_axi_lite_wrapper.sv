`timescale 1ns/1ps

module tb_aead_axi_lite_wrapper;
    logic clk=1'b0;
    logic rst_n=1'b0;
    always #5 clk=~clk;

    logic [9:0] awaddr;
    logic awvalid, awready;
    logic [31:0] wdata;
    logic [3:0] wstrb;
    logic wvalid, wready;
    logic [1:0] bresp;
    logic bvalid, bready;
    logic [9:0] araddr;
    logic arvalid, arready;
    logic [31:0] rdata;
    logic [1:0] rresp;
    logic rvalid, rready;

    logic [255:0] key;
    logic [31:0] prefix;
    logic [511:0] plaintext, ciphertext;
    logic [127:0] tag;
    logic [255:0] shared_secret,transcript_hash;
    logic [31:0] status_word, value;
    integer i, cycles, failures=0;

    function automatic [31:0] pack4(input logic [31:0] v);
        integer j;
        begin for(j=0;j<4;j=j+1) pack4[8*j+:8]=v[31-8*j-:8]; end
    endfunction
    function automatic [127:0] pack16(input logic [127:0] v);
        integer j;
        begin for(j=0;j<16;j=j+1) pack16[8*j+:8]=v[127-8*j-:8]; end
    endfunction
    function automatic [255:0] pack32(input logic [255:0] v);
        integer j;
        begin for(j=0;j<32;j=j+1) pack32[8*j+:8]=v[255-8*j-:8]; end
    endfunction
    function automatic [511:0] pack64(input logic [511:0] v);
        integer j;
        begin for(j=0;j<64;j=j+1) pack64[8*j+:8]=v[511-8*j-:8]; end
    endfunction

    aead_axi_lite_wrapper dut (
        .s_axi_aclk(clk), .s_axi_aresetn(rst_n),
        .s_axi_awaddr(awaddr), .s_axi_awvalid(awvalid),
        .s_axi_awready(awready), .s_axi_wdata(wdata),
        .s_axi_wstrb(wstrb), .s_axi_wvalid(wvalid),
        .s_axi_wready(wready), .s_axi_bresp(bresp),
        .s_axi_bvalid(bvalid), .s_axi_bready(bready),
        .s_axi_araddr(araddr), .s_axi_arvalid(arvalid),
        .s_axi_arready(arready), .s_axi_rdata(rdata),
        .s_axi_rresp(rresp), .s_axi_rvalid(rvalid),
        .s_axi_rready(rready)
    );

    task automatic axi_write(input logic [9:0] address,input logic [31:0] data);
        begin
            @(negedge clk);
            awaddr=address; awvalid=1'b1;
            wdata=data; wstrb=4'hf; wvalid=1'b1; bready=1'b1;
            while (!(awready && wready)) @(posedge clk);
            @(negedge clk); awvalid=1'b0; wvalid=1'b0;
            while (!bvalid) @(posedge clk);
            @(negedge clk); bready=1'b0;
        end
    endtask

    task automatic axi_read(input logic [9:0] address,output logic [31:0] data);
        begin
            @(negedge clk);
            araddr=address; arvalid=1'b1; rready=1'b1;
            while (!arready) @(posedge clk);
            @(negedge clk); arvalid=1'b0;
            while (!rvalid) @(posedge clk);
            #1 data=rdata;
            @(negedge clk); rready=1'b0;
        end
    endtask

    task automatic wait_done(output logic [31:0] status);
        begin
            status=32'd0; cycles=0;
            while (!status[1] && cycles<600) begin
                axi_read(10'h008,status);
                cycles=cycles+1;
            end
        end
    endtask

    initial begin
        awaddr='0; awvalid=0; wdata='0; wstrb=0; wvalid=0; bready=0;
        araddr='0; arvalid=0; rready=0;
        key=pack32(256'h71732bdafb22b7dcc949f0902c5ef420c16a945633dc87e579fe9e5b7755114a);
        prefix=pack4(32'h7d3fe84c);
        plaintext=pack64(512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000);
        ciphertext=pack64(512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a);
        tag=pack16(128'h98fe11b3409dd2e381c7711868916dcf);
        shared_secret=pack32(256'hee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f);
        transcript_hash=pack32(256'h0b727acdecaa849e1824e3b9fb450e7db285a4951bf324be08b2d941774d98b0);

        repeat(5) @(posedge clk); rst_n<=1'b1; repeat(3) @(posedge clk);

        axi_read(10'h000,value);
        if(value!==32'h0001_0000) begin $display("FAIL: AXI version register"); failures=failures+1; end
        else $display("PASS: AXI-Lite register read");

        /* Configure slot 0 with the C-golden directional material. */
        axi_write(10'h028,32'h01020304);
        for(i=0;i<8;i=i+1) begin
            axi_write(10'h040+4*i,key[32*i+:32]);
            axi_write(10'h060+4*i,key[32*i+:32]);
        end
        axi_write(10'h080,prefix);
        axi_write(10'h084,prefix);
        axi_write(10'h02c,32'h8000_0100);
        status_word=32'h10;
        while(status_word[4]) axi_read(10'h008,status_word);
        $display("PASS: AXI session configuration accepted");

        /* Encrypt the 64-byte golden plaintext. */
        axi_write(10'h00c,32'd0);
        axi_write(10'h010,32'd40);
        axi_write(10'h014,32'd0);
        axi_write(10'h018,32'd0);
        for(i=0;i<16;i=i+1) axi_write(10'h100+4*i,plaintext[32*i+:32]);
        axi_write(10'h004,32'h0000_0001);
        wait_done(status_word);
        if(cycles>=600 || !status_word[2] || status_word[3]) begin
            $display("FAIL: AXI encryption status"); failures=failures+1;
        end
        for(i=0;i<16;i=i+1) begin
            axi_read(10'h180+4*i,value);
            if(value!==ciphertext[32*i+:32]) failures=failures+1;
        end
        for(i=0;i<4;i=i+1) begin
            axi_read(10'h1c0+4*i,value);
            if(value!==tag[32*i+:32]) failures=failures+1;
        end
        if(failures==0) $display("PASS: AXI encryption matches C golden packet");

        /* Clear DONE, then authenticate and decrypt counter 0. */
        axi_write(10'h004,32'h0000_0100);
        for(i=0;i<16;i=i+1) axi_write(10'h100+4*i,ciphertext[32*i+:32]);
        for(i=0;i<4;i=i+1) axi_write(10'h140+4*i,tag[32*i+:32]);
        axi_write(10'h014,32'd0); axi_write(10'h018,32'd0);
        axi_write(10'h004,32'h0000_0003);
        wait_done(status_word);
        if(cycles>=600 || !status_word[2] || status_word[3]) begin
            $display("FAIL: AXI decrypt status"); failures=failures+1;
        end
        for(i=0;i<16;i=i+1) begin
            axi_read(10'h180+4*i,value);
            if(value!==plaintext[32*i+:32]) failures=failures+1;
        end
        if(!status_word[3] && status_word[2])
            $display("PASS: AXI authenticated decrypt returns plaintext");

        /* Reusing RX counter 0 must be rejected. */
        axi_write(10'h004,32'h0000_0100);
        axi_write(10'h004,32'h0000_0003);
        wait_done(status_word);
        if(cycles>=600 || status_word[2] || !status_word[3]) begin
            $display("FAIL: AXI replay rejection status"); failures=failures+1;
        end else begin
            $display("PASS: AXI replayed counter rejected");
        end

        /* Install slot 1 directly from the ML-KEM result through the PL KDF. */
        axi_write(10'h00c,32'd1); axi_write(10'h028,32'h01020304);
        for(i=0;i<8;i=i+1) begin
            axi_write(10'h204+4*i,shared_secret[32*i+:32]);
            axi_write(10'h224+4*i,transcript_hash[32*i+:32]);
        end
        axi_write(10'h200,32'd1);
        status_word=32'h50;
        while(status_word[6]||status_word[4]) axi_read(10'h008,status_word);
        $display("PASS: AXI ML-KEM result derives and installs slot 1");

        ciphertext=pack64(512'hb7b235da3dbbb9ecd92eca9019e9223a368ca0aad5fd167f9c86595d727381cb0ecf98c4fd286c963ffe346c8644bd72386083ca105e9f23cdbc2697877d85fa);
        tag=pack16(128'h0b8552e36371bcd72ab7f0aba138952c);
        axi_write(10'h004,32'h0000_0100);
        for(i=0;i<16;i=i+1)axi_write(10'h100+4*i,plaintext[32*i+:32]);
        axi_write(10'h004,32'h0000_0001);wait_done(status_word);
        for(i=0;i<16;i=i+1)begin axi_read(10'h180+4*i,value);
            if(value!==ciphertext[32*i+:32])failures=failures+1;end
        for(i=0;i<4;i=i+1)begin axi_read(10'h1c0+4*i,value);
            if(value!==tag[32*i+:32])failures=failures+1;end
        if(status_word[2]&&!status_word[3])
            $display("PASS: AXI slot 1 uses derived ZB->PC key");
        else failures=failures+1;

        if(failures==0) $display("ALL AXI WRAPPER TESTS PASSED");
        else $display("AXI WRAPPER TESTS FAILED: %0d failure(s)",failures);
        $finish;
    end
endmodule
