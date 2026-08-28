`timescale 1ns/1ps

module tb_aead_session_manager_bram;
    localparam integer NUM_SESSIONS = 64;
    localparam integer SLOT_WIDTH = 6;

    logic clk = 1'b0;
    logic rst_n = 1'b0;
    always #5 clk = ~clk;

    logic cfg_write, cfg_valid, cfg_ready, cfg_done;
    logic [SLOT_WIDTH-1:0] cfg_slot;
    logic [31:0] cfg_session_id;
    logic [255:0] cfg_tx_key, cfg_rx_key;
    logic [31:0] cfg_tx_prefix, cfg_rx_prefix;

    logic req_valid, req_ready, req_decrypt;
    logic [SLOT_WIDTH-1:0] req_slot;
    logic [7:0] req_len;
    logic [63:0] req_counter;
    logic [511:0] req_data;
    logic [127:0] req_tag;

    logic rsp_valid, rsp_ready, rsp_auth, rsp_error;
    logic [SLOT_WIDTH-1:0] rsp_slot;
    logic [63:0] rsp_counter;
    logic [511:0] rsp_data;
    logic [127:0] rsp_tag;

    logic [255:0] key;
    logic [31:0] prefix;
    logic [511:0] plaintext, ciphertext;
    logic [127:0] golden_tag;
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

    aead_session_manager_bram #(
        .NUM_SESSIONS(NUM_SESSIONS), .SLOT_WIDTH(SLOT_WIDTH)
    ) dut (
        .clk_i(clk), .rst_ni(rst_n), .cfg_write_i(cfg_write),
        .cfg_slot_i(cfg_slot), .cfg_valid_i(cfg_valid),
        .cfg_session_id_i(cfg_session_id), .cfg_tx_key_i(cfg_tx_key),
        .cfg_rx_key_i(cfg_rx_key), .cfg_tx_nonce_prefix_i(cfg_tx_prefix),
        .cfg_rx_nonce_prefix_i(cfg_rx_prefix), .cfg_ready_o(cfg_ready),
        .cfg_done_o(cfg_done), .req_valid_i(req_valid),
        .req_ready_o(req_ready), .req_slot_i(req_slot),
        .req_decrypt_i(req_decrypt), .req_data_len_i(req_len),
        .req_counter_i(req_counter), .req_data_i(req_data),
        .req_tag_i(req_tag), .rsp_valid_o(rsp_valid),
        .rsp_ready_i(rsp_ready), .rsp_auth_ok_o(rsp_auth),
        .rsp_error_o(rsp_error), .rsp_slot_o(rsp_slot),
        .rsp_counter_o(rsp_counter), .rsp_data_o(rsp_data),
        .rsp_tag_o(rsp_tag)
    );

    task automatic configure(input logic [SLOT_WIDTH-1:0] slot);
        begin
            wait (cfg_ready);
            @(negedge clk);
            cfg_slot  = slot;
            cfg_write = 1'b1;
            cfg_valid = 1'b1;
            @(posedge clk);
            @(negedge clk);
            cfg_write = 1'b0;
            wait (cfg_done);
            @(posedge clk);
        end
    endtask

    task automatic request(
        input logic [SLOT_WIDTH-1:0] slot,
        input logic decrypt,
        input logic [63:0] counter,
        input logic [511:0] data,
        input logic [127:0] tag);
        begin
            wait (req_ready);
            @(negedge clk);
            req_slot    = slot;
            req_decrypt = decrypt;
            req_counter = counter;
            req_data    = data;
            req_tag     = tag;
            req_valid   = 1'b1;
            @(posedge clk);
            @(negedge clk);
            req_valid = 1'b0;
            cycles = 0;
            while (!rsp_valid && cycles < 1000) begin
                @(posedge clk);
                cycles = cycles + 1;
            end
            #1;
            if (cycles >= 1000) begin
                $display("FAIL: slot %0d request timeout", slot);
                failures = failures + 1;
            end
        end
    endtask

    task automatic consume;
        begin
            @(negedge clk);
            rsp_ready = 1'b1;
            @(posedge clk);
            @(negedge clk);
            rsp_ready = 1'b0;
        end
    endtask

    initial begin
        cfg_write = 0;
        cfg_valid = 0;
        cfg_slot = 0;
        cfg_session_id = 32'h01020304;
        cfg_tx_key = 0;
        cfg_rx_key = 0;
        cfg_tx_prefix = 0;
        cfg_rx_prefix = 0;
        req_valid = 0;
        req_slot = 0;
        req_decrypt = 0;
        req_len = 8'd40;
        req_counter = 0;
        req_data = 0;
        req_tag = 0;
        rsp_ready = 0;

        key = pack32(256'h71732bdafb22b7dcc949f0902c5ef420c16a945633dc87e579fe9e5b7755114a);
        prefix = pack4(32'h7d3fe84c);
        plaintext = pack64(512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000);
        ciphertext = pack64(512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a);
        golden_tag = pack16(128'h98fe11b3409dd2e381c7711868916dcf);
        cfg_tx_key = key;
        cfg_rx_key = key;
        cfg_tx_prefix = prefix;
        cfg_rx_prefix = prefix;

        repeat (4) @(posedge clk);
        rst_n = 1'b1;
        repeat (2) @(posedge clk);

        configure(6'd0);
        configure(6'd63);

        request(6'd0, 1'b0, 64'd0, plaintext, 128'd0);
        if (!rsp_auth || rsp_error || rsp_slot != 6'd0 || rsp_counter != 0
            || rsp_data !== ciphertext || rsp_tag !== golden_tag) begin
            $display("FAIL: slot 0 golden encryption");
            failures = failures + 1;
        end else $display("PASS: slot 0 golden encryption");
        consume();

        request(6'd63, 1'b0, 64'd0, plaintext, 128'd0);
        if (!rsp_auth || rsp_error || rsp_slot != 6'd63 || rsp_counter != 0
            || rsp_data !== ciphertext || rsp_tag !== golden_tag) begin
            $display("FAIL: slot 63 independent golden encryption");
            failures = failures + 1;
        end else $display("PASS: slot 63 independent golden encryption");
        consume();

        request(6'd0, 1'b0, 64'd0, plaintext, 128'd0);
        if (!rsp_auth || rsp_error || rsp_counter != 1) begin
            $display("FAIL: slot 0 TX counter did not advance independently");
            failures = failures + 1;
        end else $display("PASS: slot 0 TX counter is independent from slot 63");
        consume();

        request(6'd63, 1'b1, 64'd0, ciphertext, golden_tag);
        if (!rsp_auth || rsp_error || rsp_data !== plaintext) begin
            $display("FAIL: slot 63 authenticated decrypt");
            failures = failures + 1;
        end else $display("PASS: slot 63 authenticated decrypt");
        consume();

        request(6'd63, 1'b1, 64'd0, ciphertext, golden_tag);
        if (rsp_auth || !rsp_error || rsp_data !== 0) begin
            $display("FAIL: slot 63 replay was not rejected");
            failures = failures + 1;
        end else $display("PASS: slot 63 replay rejected fail-closed");
        consume();

        request(6'd32, 1'b0, 64'd0, plaintext, 128'd0);
        if (rsp_auth || !rsp_error || rsp_data !== 0) begin
            $display("FAIL: unconfigured slot accepted");
            failures = failures + 1;
        end else $display("PASS: unconfigured slot rejected");
        consume();

        if (failures == 0)
            $display("ALL 64-SESSION BRAM MANAGER TESTS PASSED");
        else
            $fatal(1, "64-session BRAM manager failures: %0d", failures);
        $finish;
    end

    initial begin
        #200000;
        $fatal(1, "64-session BRAM manager timeout");
    end
endmodule
