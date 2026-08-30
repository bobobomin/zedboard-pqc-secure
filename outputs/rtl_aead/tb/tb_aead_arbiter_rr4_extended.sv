`timescale 1ns/1ps

module tb_aead_arbiter_rr4_extended;
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

    integer failures = 0;
    integer cycles;
    integer grants;
    integer responses;
    integer grant_count [0:3];

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
            wait (cfg_ready);
            @(negedge clk);
            cfg_slot = slot;
            cfg_write = 1'b1;
            cfg_valid = 1'b1;
            @(negedge clk);
            cfg_write = 1'b0;
        end
    endtask

    function automatic [3:0] expected_first_round(input integer index);
        case (index)
            0: expected_first_round = 4'b0001;
            1: expected_first_round = 4'b0010;
            2: expected_first_round = 4'b0100;
            default: expected_first_round = 4'b1000;
        endcase
    endfunction

    function automatic [3:0] expected_persistent(input integer index);
        case (index % 4)
            0: expected_persistent = 4'b1000;
            1: expected_persistent = 4'b0001;
            2: expected_persistent = 4'b0010;
            default: expected_persistent = 4'b0100;
        endcase
    endfunction

    initial begin
        cfg_write = 0;
        cfg_valid = 0;
        cfg_slot = 0;
        cfg_session_id = 32'h01020304;
        cfg_tx_key = 256'h71732bdafb22b7dcc949f0902c5ef420c16a945633dc87e579fe9e5b7755114a;
        cfg_rx_key = cfg_tx_key;
        cfg_tx_prefix = 32'h7d3fe84c;
        cfg_rx_prefix = cfg_tx_prefix;
        req_valid = 0;
        req_decrypt = 0;
        req_data_len = {4{8'd40}};
        req_counter = 0;
        req_data = 0;
        req_tag = 0;
        rsp_ready = 4'b1111;

        repeat (4) @(posedge clk);
        rst_n = 1'b1;
        repeat (2) @(posedge clk);

        configure_slot(0);
        configure_slot(1);
        configure_slot(2);
        configure_slot(3);

        /* Reset last_grant is slot 3, so four simultaneous requests must
           be accepted in slot 0, 1, 2, 3 order. */
        @(negedge clk);
        req_valid = 4'b1111;
        grants = 0;
        responses = 0;
        cycles = 0;
        while ((responses < 4) && (cycles < 5000)) begin
            @(posedge clk);
            if (|req_ready) begin
                if (req_ready !== expected_first_round(grants)) begin
                    $display("FAIL: first round grant %0d was %b", grants, req_ready);
                    failures = failures + 1;
                end
                req_valid <= req_valid & ~req_ready;
                grants = grants + 1;
            end
            if (|rsp_valid) begin
                if ((rsp_auth_ok & rsp_valid) !== rsp_valid || |(rsp_error & rsp_valid)) begin
                    $display("FAIL: first round response error %b", rsp_valid);
                    failures = failures + 1;
                end
                responses = responses + 1;
            end
            cycles = cycles + 1;
        end
        if (grants != 4 || responses != 4) begin
            $display("FAIL: four-slot round did not finish grants=%0d responses=%0d", grants, responses);
            failures = failures + 1;
        end else begin
            $display("PASS: simultaneous slots are served 0,1,2,3");
        end

        /* Last winner was slot 3. With only slot 0 and 2 requesting,
           the arbiter must serve slot 0 and then skip slot 1 to slot 2. */
        repeat (2) @(posedge clk);
        @(negedge clk);
        req_valid = 4'b0101;
        grants = 0;
        responses = 0;
        cycles = 0;
        while ((responses < 2) && (cycles < 3000)) begin
            @(posedge clk);
            if (|req_ready) begin
                if ((grants == 0 && req_ready !== 4'b0001) ||
                    (grants == 1 && req_ready !== 4'b0100)) begin
                    $display("FAIL: skip test grant %0d was %b", grants, req_ready);
                    failures = failures + 1;
                end
                req_valid <= req_valid & ~req_ready;
                grants = grants + 1;
            end
            if (|rsp_valid)
                responses = responses + 1;
            cycles = cycles + 1;
        end
        if (grants != 2 || responses != 2) begin
            $display("FAIL: inactive-slot skip test did not finish");
            failures = failures + 1;
        end else begin
            $display("PASS: inactive slots are skipped without blocking");
        end

        /* Last winner is slot 2. Keep all requesters asserted for eight
           grants. Expected order is 3,0,1,2 twice, proving no starvation. */
        repeat (2) @(posedge clk);
        for (integer i = 0; i < 4; i = i + 1)
            grant_count[i] = 0;
        @(negedge clk);
        req_valid = 4'b1111;
        grants = 0;
        responses = 0;
        cycles = 0;
        while ((responses < 8) && (cycles < 10000)) begin
            @(posedge clk);
            if (|req_ready) begin
                if (req_ready !== expected_persistent(grants)) begin
                    $display("FAIL: persistent grant %0d was %b", grants, req_ready);
                    failures = failures + 1;
                end
                if (req_ready[0]) grant_count[0] = grant_count[0] + 1;
                if (req_ready[1]) grant_count[1] = grant_count[1] + 1;
                if (req_ready[2]) grant_count[2] = grant_count[2] + 1;
                if (req_ready[3]) grant_count[3] = grant_count[3] + 1;
                grants = grants + 1;
                if (grants == 8)
                    req_valid <= 4'b0000;
            end
            if (|rsp_valid)
                responses = responses + 1;
            cycles = cycles + 1;
        end
        if (grants != 8 || responses != 8 ||
            grant_count[0] != 2 || grant_count[1] != 2 ||
            grant_count[2] != 2 || grant_count[3] != 2) begin
            $display("FAIL: starvation/fairness counts %0d %0d %0d %0d",
                     grant_count[0], grant_count[1], grant_count[2], grant_count[3]);
            failures = failures + 1;
        end else begin
            $display("PASS: persistent contention is fair; every slot wins twice");
        end

        if (failures == 0)
            $display("ALL EXTENDED ROUND-ROBIN TESTS PASSED");
        else
            $display("EXTENDED ROUND-ROBIN TESTS FAILED: %0d", failures);
        $finish;
    end
endmodule
