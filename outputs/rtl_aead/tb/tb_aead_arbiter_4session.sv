`timescale 1ns/1ps

module tb_aead_arbiter_4session;
    logic clk = 1'b0;
    logic rst_n = 1'b0;
    always #5 clk = ~clk;

    logic cfg_write, cfg_valid, cfg_ready;
    logic [1:0] cfg_slot;
    logic [31:0] cfg_session_id;
    logic [255:0] cfg_tx_key, cfg_rx_key;
    logic [31:0] cfg_tx_prefix, cfg_rx_prefix;

    logic [3:0] req_valid, req_ready, req_decrypt;
    logic [31:0] req_data_len;
    logic [255:0] req_counter;
    logic [2047:0] req_data;
    logic [511:0] req_tag;

    logic [3:0] rsp_valid, rsp_ready, rsp_auth_ok, rsp_error;
    logic [255:0] rsp_counter;
    logic [2047:0] rsp_data;
    logic [511:0] rsp_tag;

    logic [255:0] key;
    logic [31:0] prefix;
    logic [511:0] plaintext, ciphertext;
    logic [127:0] tag;
    integer failures = 0;
    integer cycles;

    function automatic [31:0] pack4(input logic [31:0] value);
        integer j;
        begin
            for (j=0; j<4; j=j+1)
                pack4[8*j +: 8] = value[31-8*j -: 8];
        end
    endfunction

    function automatic [127:0] pack16(input logic [127:0] value);
        integer j;
        begin
            for (j=0; j<16; j=j+1)
                pack16[8*j +: 8] = value[127-8*j -: 8];
        end
    endfunction

    function automatic [255:0] pack32(input logic [255:0] value);
        integer j;
        begin
            for (j=0; j<32; j=j+1)
                pack32[8*j +: 8] = value[255-8*j -: 8];
        end
    endfunction

    function automatic [511:0] pack64(input logic [511:0] value);
        integer j;
        begin
            for (j=0; j<64; j=j+1)
                pack64[8*j +: 8] = value[511-8*j -: 8];
        end
    endfunction

    aead_arbiter_4session dut (
        .clk_i(clk), .rst_ni(rst_n),
        .cfg_write_i(cfg_write), .cfg_slot_i(cfg_slot),
        .cfg_valid_i(cfg_valid), .cfg_session_id_i(cfg_session_id),
        .cfg_tx_key_i(cfg_tx_key), .cfg_rx_key_i(cfg_rx_key),
        .cfg_tx_nonce_prefix_i(cfg_tx_prefix),
        .cfg_rx_nonce_prefix_i(cfg_rx_prefix), .cfg_ready_o(cfg_ready),
        .req_valid_i(req_valid), .req_ready_o(req_ready),
        .req_decrypt_i(req_decrypt), .req_data_len_i(req_data_len),
        .req_counter_i(req_counter), .req_data_i(req_data),
        .req_tag_i(req_tag), .rsp_valid_o(rsp_valid),
        .rsp_ready_i(rsp_ready), .rsp_auth_ok_o(rsp_auth_ok),
        .rsp_error_o(rsp_error), .rsp_counter_o(rsp_counter),
        .rsp_data_o(rsp_data), .rsp_tag_o(rsp_tag)
    );

    task automatic configure_slot(input logic [1:0] slot);
        begin
            @(posedge clk);
            cfg_slot       <= slot;
            cfg_write      <= 1'b1;
            cfg_valid      <= 1'b1;
            cfg_session_id <= 32'h01020304;
            cfg_tx_key     <= key;
            cfg_rx_key     <= key;
            cfg_tx_prefix  <= prefix;
            cfg_rx_prefix  <= prefix;
            @(posedge clk);
            cfg_write <= 1'b0;
        end
    endtask

    task automatic consume_response(input logic [1:0] slot);
        begin
            @(posedge clk);
            rsp_ready[slot] <= 1'b1;
            @(posedge clk);
            rsp_ready[slot] <= 1'b0;
        end
    endtask

    initial begin
        cfg_write = 1'b0; cfg_valid = 1'b0; cfg_slot = '0;
        cfg_session_id = '0; cfg_tx_key = '0; cfg_rx_key = '0;
        cfg_tx_prefix = '0; cfg_rx_prefix = '0;
        req_valid = '0; req_decrypt = '0; req_data_len = '0;
        req_counter = '0; req_data = '0; req_tag = '0;
        rsp_ready = '0;

        key = pack32(256'h71732bdafb22b7dcc949f0902c5ef420c16a945633dc87e579fe9e5b7755114a);
        prefix = pack4(32'h7d3fe84c);
        plaintext = pack64(512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000);
        ciphertext = pack64(512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a);
        tag = pack16(128'h98fe11b3409dd2e381c7711868916dcf);

        repeat (4) @(posedge clk);
        rst_n <= 1'b1;
        repeat (2) @(posedge clk);
        configure_slot(2'd0);
        configure_slot(2'd1);

        /* Slot 0 encryption: arbiter builds the golden counter-0 nonce/AAD. */
        @(posedge clk);
        req_decrypt[0] = 1'b0;
        req_data_len[7:0] = 8'd40;
        req_data[511:0] = plaintext;
        req_valid[0] = 1'b1;
        wait (req_ready[0]);
        @(posedge clk); req_valid[0] <= 1'b0;
        cycles = 0;
        while (!rsp_valid[0] && cycles < 500) begin @(posedge clk); cycles=cycles+1; end
        #1;
        if (cycles >= 500 || !rsp_auth_ok[0] || rsp_error[0]
            || rsp_counter[63:0] != 64'd0
            || rsp_data[511:0] !== ciphertext
            || rsp_tag[127:0] !== tag) begin
            $display("FAIL: arbiter encryption/golden packet mismatch");
            failures = failures + 1;
        end else $display("PASS: arbiter slot0 encryption matches C golden packet");
        consume_response(2'd0);

        /* Slot 0 RX counter 0 authenticates and releases plaintext. */
        @(posedge clk);
        req_decrypt[0] = 1'b1;
        req_counter[63:0] = 64'd0;
        req_data[511:0] = ciphertext;
        req_tag[127:0] = tag;
        req_valid[0] = 1'b1;
        wait (req_ready[0]);
        @(posedge clk); req_valid[0] <= 1'b0;
        cycles = 0;
        while (!rsp_valid[0] && cycles < 500) begin @(posedge clk); cycles=cycles+1; end
        #1;
        if (cycles >= 500 || !rsp_auth_ok[0] || rsp_error[0]
            || rsp_data[511:0] !== plaintext) begin
            $display("FAIL: arbiter authenticated decrypt mismatch");
            failures = failures + 1;
        end else $display("PASS: arbiter authenticates before releasing plaintext");
        consume_response(2'd0);

        /* Reusing RX counter 0 is rejected before the crypto engine runs. */
        @(posedge clk);
        req_valid[0] = 1'b1;
        wait (req_ready[0]);
        @(posedge clk); req_valid[0] <= 1'b0;
        cycles = 0;
        while (!rsp_valid[0] && cycles < 30) begin @(posedge clk); cycles=cycles+1; end
        #1;
        if (cycles >= 30 || rsp_auth_ok[0] || !rsp_error[0]
            || rsp_data[511:0] !== 512'd0) begin
            $display("FAIL: replayed counter was not rejected");
            failures = failures + 1;
        end else $display("PASS: replayed RX counter rejected");
        consume_response(2'd0);

        /* Expected counter 1 passes replay check but a bad tag fails closed. */
        @(posedge clk);
        req_counter[63:0] = 64'd1;
        req_data[511:0] = ciphertext ^ 512'd1;
        req_valid[0] = 1'b1;
        wait (req_ready[0]);
        @(posedge clk); req_valid[0] <= 1'b0;
        cycles = 0;
        while (!rsp_valid[0] && cycles < 500) begin @(posedge clk); cycles=cycles+1; end
        #1;
        if (cycles >= 500 || rsp_auth_ok[0] || !rsp_error[0]
            || rsp_data[511:0] !== 512'd0) begin
            $display("FAIL: modified ciphertext was not rejected fail-closed");
            failures = failures + 1;
        end else $display("PASS: modified ciphertext rejected with zero plaintext");
        consume_response(2'd0);

        /* After slot 0 won last, simultaneous slot 0/1 requests grant slot 1. */
        @(posedge clk);
        req_decrypt[1:0] = 2'b00;
        req_data_len[15:0] = {8'd40, 8'd40};
        req_data[1023:0] = {plaintext, plaintext};
        req_valid[1:0] = 2'b11;
        #1;
        if (req_ready[1:0] !== 2'b10) begin
            $display("FAIL: round-robin did not select slot1 after slot0");
            failures = failures + 1;
        end else $display("PASS: round-robin selects the next requesting session");
        @(posedge clk); req_valid[1:0] <= 2'b00;
        cycles = 0;
        while (!rsp_valid[1] && cycles < 500) begin @(posedge clk); cycles=cycles+1; end
        #1;
        if (cycles >= 500 || !rsp_auth_ok[1] || rsp_error[1]) begin
            $display("FAIL: slot1 round-robin request did not complete");
            failures = failures + 1;
        end else $display("PASS: slot1 request completes on the shared AEAD engine");
        consume_response(2'd1);

        if (failures == 0)
            $display("ALL ARBITER TESTS PASSED");
        else
            $display("ARBITER TESTS FAILED: %0d failure(s)", failures);
        $finish;
    end
endmodule
