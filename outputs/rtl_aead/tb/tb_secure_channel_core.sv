`timescale 1ns/1ps
module tb_secure_channel_core;
    logic clk=0,rst_n=0,hs_start,hs_busy,hs_done;
    logic [1:0] hs_slot;logic [31:0] hs_session;
    logic [255:0] hs_secret,hs_hash;
    logic [3:0] req_valid,req_ready,req_decrypt,rsp_valid,rsp_ready,rsp_auth,rsp_error;
    logic [31:0] req_len;logic [255:0] req_counter,rsp_counter;
    logic [2047:0] req_data,rsp_data;logic [511:0] req_tag,rsp_tag;
    integer i;
    always #5 clk=~clk;
    function automatic [255:0] pack32(input [255:0] x);integer j;begin
        for(j=0;j<32;j=j+1)pack32[8*j+:8]=x[255-8*j-:8];end endfunction
    function automatic [511:0] pack64(input [511:0] x);integer j;begin
        for(j=0;j<64;j=j+1)pack64[8*j+:8]=x[511-8*j-:8];end endfunction
    function automatic [127:0] pack16(input [127:0] x);integer j;begin
        for(j=0;j<16;j=j+1)pack16[8*j+:8]=x[127-8*j-:8];end endfunction

    secure_channel_core dut(.clk_i(clk),.rst_ni(rst_n),
        .handshake_start_i(hs_start),.handshake_slot_i(hs_slot),
        .handshake_session_id_i(hs_session),.handshake_shared_secret_i(hs_secret),
        .handshake_transcript_hash_i(hs_hash),.handshake_busy_o(hs_busy),
        .handshake_done_o(hs_done),.req_valid_i(req_valid),.req_ready_o(req_ready),
        .req_decrypt_i(req_decrypt),.req_data_len_i(req_len),
        .req_counter_i(req_counter),.req_data_i(req_data),.req_tag_i(req_tag),
        .rsp_valid_o(rsp_valid),.rsp_ready_i(rsp_ready),.rsp_auth_ok_o(rsp_auth),
        .rsp_error_o(rsp_error),.rsp_counter_o(rsp_counter),
        .rsp_data_o(rsp_data),.rsp_tag_o(rsp_tag));

    initial begin
        hs_start=0;hs_slot=0;hs_session=32'h01020304;
        hs_secret=pack32(256'hee5f8f90fb6f15a5934504e1f65c23ad2d60964104bf42463876363a799dee4f);
        hs_hash=pack32(256'h0b727acdecaa849e1824e3b9fb450e7db285a4951bf324be08b2d941774d98b0);
        req_valid=0;req_decrypt=0;req_len=0;req_counter=0;req_data=0;req_tag=0;rsp_ready=0;
        repeat(4)@(posedge clk);rst_n=1;@(posedge clk);
        hs_start=1;@(posedge clk);#1;hs_start=0;
        wait(hs_done);@(posedge clk);#1;
        $display("PASS ML-KEM shared secret -> SHAKE256 KDF -> session slot");

        req_len[7:0]=40;
        req_data[511:0]=pack64(512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000);
        req_valid[0]=1;wait(req_ready[0]);@(posedge clk);#1;req_valid[0]=0;
        wait(rsp_valid[0]);#1;
        if(!rsp_auth[0]||rsp_error[0]||rsp_data[511:0]!==pack64(512'hb7b235da3dbbb9ecd92eca9019e9223a368ca0aad5fd167f9c86595d727381cb0ecf98c4fd286c963ffe346c8644bd72386083ca105e9f23cdbc2697877d85fa)
          ||rsp_tag[127:0]!==pack16(128'h0b8552e36371bcd72ab7f0aba138952c))
            $fatal(1,"ZB TX encryption mismatch after KDF connection");
        $display("PASS ZB TX uses derived ZB->PC key/prefix");
        rsp_ready[0]=1;@(posedge clk);#1;rsp_ready[0]=0;

        req_decrypt[0]=1;req_counter[63:0]=0;
        req_data[511:0]=pack64(512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a);
        req_tag[127:0]=pack16(128'h98fe11b3409dd2e381c7711868916dcf);
        req_valid[0]=1;wait(req_ready[0]);@(posedge clk);#1;req_valid[0]=0;
        wait(rsp_valid[0]);#1;
        if(!rsp_auth[0]||rsp_error[0]||rsp_data[511:0]!==pack64(512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000))
            $fatal(1,"PC RX decryption mismatch after KDF connection");
        $display("PASS ZB RX uses derived PC->ZB key/prefix and authenticates packet");
        $display("ALL SECURE CHANNEL CONNECTION TESTS PASSED");$finish;
    end
endmodule
