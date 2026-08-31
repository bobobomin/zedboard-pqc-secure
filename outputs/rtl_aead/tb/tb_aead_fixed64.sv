`timescale 1ns/1ps

module tb_aead_fixed64;

    logic clk = 1'b0;
    logic rst_n = 1'b0;
    always #5 clk = ~clk;

    logic chacha_start;
    logic [31:0] chacha_counter;
    logic chacha_busy, chacha_done;
    logic [511:0] chacha_result;

    logic poly_start;
    logic poly_busy, poly_done;
    logic [767:0] poly_message;
    logic [127:0] poly_result;

    logic aead_start;
    logic aead_busy, aead_done;
    logic [511:0] aead_ciphertext;
    logic [127:0] aead_tag;

    logic decrypt_start;
    logic decrypt_busy, decrypt_done, decrypt_auth_ok;
    logic [511:0] decrypt_ciphertext;
    logic [127:0] decrypt_received_tag;
    logic [511:0] decrypt_plaintext;

    logic [255:0] key;
    logic [95:0] nonce;
    logic [127:0] aad;
    logic [511:0] plaintext;
    logic [255:0] poly_key;

    logic [511:0] expected_keystream;
    logic [511:0] expected_ciphertext;
    logic [127:0] expected_tag;

    integer failures = 0;
    integer cycles;

    function automatic [95:0] pack12(input logic [95:0] value);
        integer j;
        begin
            for (j = 0; j < 12; j = j + 1)
                pack12[8*j +: 8] = value[95-8*j -: 8];
        end
    endfunction

    function automatic [127:0] pack16(input logic [127:0] value);
        integer j;
        begin
            for (j = 0; j < 16; j = j + 1)
                pack16[8*j +: 8] = value[127-8*j -: 8];
        end
    endfunction

    function automatic [255:0] pack32(input logic [255:0] value);
        integer j;
        begin
            for (j = 0; j < 32; j = j + 1)
                pack32[8*j +: 8] = value[255-8*j -: 8];
        end
    endfunction

    function automatic [511:0] pack64(input logic [511:0] value);
        integer j;
        begin
            for (j = 0; j < 64; j = j + 1)
                pack64[8*j +: 8] = value[511-8*j -: 8];
        end
    endfunction

    chacha20_block u_chacha_dut (
        .clk_i(clk), .rst_ni(rst_n), .start_i(chacha_start),
        .key_i(key), .nonce_i(nonce), .block_counter_i(chacha_counter),
        .busy_o(chacha_busy), .done_o(chacha_done), .block_o(chacha_result)
    );

    poly1305_fixed96 u_poly_dut (
        .clk_i(clk), .rst_ni(rst_n), .start_i(poly_start),
        .one_time_key_i(poly_key), .message_i(poly_message),
        .busy_o(poly_busy), .done_o(poly_done), .tag_o(poly_result)
    );

    aead_fixed64_wrapper u_aead_dut (
        .clk_i(clk), .rst_ni(rst_n), .start_i(aead_start),
        .key_i(key), .nonce_i(nonce), .aad_i(aad),
        .plaintext_i(plaintext), .busy_o(aead_busy), .done_o(aead_done),
        .ciphertext_o(aead_ciphertext), .tag_o(aead_tag)
    );

    aead_fixed64_decrypt_wrapper u_decrypt_dut (
        .clk_i(clk), .rst_ni(rst_n), .start_i(decrypt_start),
        .key_i(key), .nonce_i(nonce), .aad_i(aad),
        .ciphertext_i(decrypt_ciphertext),
        .received_tag_i(decrypt_received_tag),
        .busy_o(decrypt_busy), .done_o(decrypt_done),
        .auth_ok_o(decrypt_auth_ok), .plaintext_o(decrypt_plaintext)
    );

    initial begin
        chacha_start   = 1'b0;
        chacha_counter = 32'd1;
        poly_start     = 1'b0;
        aead_start     = 1'b0;
        decrypt_start  = 1'b0;
        decrypt_ciphertext = '0;
        decrypt_received_tag = '0;
        poly_message   = '0;

        key = pack32(256'h71732bdafb22b7dcc949f0902c5ef420c16a945633dc87e579fe9e5b7755114a);
        nonce = pack12(96'h7d3fe84c0000000000000000);
        aad = pack16(128'h01020304000000000000000028000000);
        plaintext = pack64(512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000);
        poly_key = pack32(256'h078a3f98d451cd098170935a5fba42888e2310375cc497ea504f4501badc1ed3);

        expected_keystream = pack64(512'h5b57d889101e6376fc08551c232b96104f6107529df522492be4edbcd1037e586d8105b08ef1518095482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a);
        expected_ciphertext = pack64(512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a);
        expected_tag = pack16(128'h98fe11b3409dd2e381c7711868916dcf);

        poly_message[127:0]   = aad;
        poly_message[639:128] = expected_ciphertext;
        poly_message[767:640] = {64'd64, 64'd16};

        repeat (4) @(posedge clk);
        rst_n <= 1'b1;
        repeat (2) @(posedge clk);

        /* 1. Standalone ChaCha20 counter=1 block test. */
        chacha_start <= 1'b1;
        @(posedge clk);
        chacha_start <= 1'b0;
        cycles = 0;
        while (!chacha_done && cycles < 100) begin
            @(posedge clk);
            cycles = cycles + 1;
        end
        #1;
        if (cycles >= 100 || chacha_result !== expected_keystream) begin
            $display("FAIL: ChaCha20 counter=1 block mismatch");
            $display("  got      = %h", chacha_result);
            $display("  expected = %h", expected_keystream);
            failures = failures + 1;
        end else begin
            $display("PASS: ChaCha20 counter=1 block matches C golden vector");
        end

        /* 2. Standalone Poly1305 fixed 96-byte test. */
        @(posedge clk);
        poly_start <= 1'b1;
        @(posedge clk);
        poly_start <= 1'b0;
        cycles = 0;
        while (!poly_done && cycles < 600) begin
            @(posedge clk);
            cycles = cycles + 1;
        end
        #1;
        if (cycles >= 600 || poly_result !== expected_tag) begin
            $display("FAIL: Poly1305 tag mismatch");
            $display("  got      = %h", poly_result);
            $display("  expected = %h", expected_tag);
            failures = failures + 1;
        end else begin
            $display("PASS: Poly1305 tag matches C golden vector");
        end

        /* 3. Integrated fixed-64 AEAD wrapper test. */
        @(posedge clk);
        aead_start <= 1'b1;
        @(posedge clk);
        aead_start <= 1'b0;
        cycles = 0;
        while (!aead_done && cycles < 1200) begin
            @(posedge clk);
            cycles = cycles + 1;
        end
        #1;
        if (cycles >= 1200 || aead_ciphertext !== expected_ciphertext) begin
            $display("FAIL: AEAD ciphertext mismatch");
            $display("  got      = %h", aead_ciphertext);
            $display("  expected = %h", expected_ciphertext);
            failures = failures + 1;
        end else begin
            $display("PASS: AEAD ciphertext matches C golden vector");
        end

        if (cycles >= 1200 || aead_tag !== expected_tag) begin
            $display("FAIL: AEAD tag mismatch");
            $display("  got      = %h", aead_tag);
            $display("  expected = %h", expected_tag);
            failures = failures + 1;
        end else begin
            $display("PASS: AEAD tag matches C golden vector");
        end

        /* 4. Valid packet decrypts only after successful authentication. */
        @(posedge clk);
        decrypt_ciphertext   <= expected_ciphertext;
        decrypt_received_tag <= expected_tag;
        decrypt_start        <= 1'b1;
        @(posedge clk);
        decrypt_start <= 1'b0;
        cycles = 0;
        while (!decrypt_done && cycles < 1200) begin
            @(posedge clk);
            cycles = cycles + 1;
        end
        #1;
        if (cycles >= 1200 || !decrypt_auth_ok || decrypt_plaintext !== plaintext) begin
            $display("FAIL: authenticated decrypt mismatch");
            failures = failures + 1;
        end else begin
            $display("PASS: authenticated decrypt releases the golden plaintext");
        end

        /* 5. One-bit ciphertext tampering must not release plaintext. */
        @(posedge clk);
        decrypt_ciphertext   <= expected_ciphertext ^ 512'd1;
        decrypt_received_tag <= expected_tag;
        decrypt_start        <= 1'b1;
        @(posedge clk);
        decrypt_start <= 1'b0;
        cycles = 0;
        while (!decrypt_done && cycles < 1200) begin
            @(posedge clk);
            cycles = cycles + 1;
        end
        #1;
        if (cycles >= 1200 || decrypt_auth_ok || decrypt_plaintext !== 512'd0) begin
            $display("FAIL: tampered packet was not rejected fail-closed");
            failures = failures + 1;
        end else begin
            $display("PASS: one-bit tampering rejected with zero plaintext output");
        end

        if (failures == 0)
            $display("ALL RTL TESTS PASSED");
        else
            $display("RTL TESTS FAILED: %0d failure(s)", failures);

        $finish;
    end

endmodule
