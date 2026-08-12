`timescale 1ns/1ps

module tb_sha3_shake_stream;
    logic clk=0, rst_n=0, start, input_valid, finalize, output_ready;
    logic [1:0] mode;
    logic [15:0] output_length;
    logic [7:0] input_byte, output_byte;
    logic input_ready, output_valid, busy, done;
    logic [7:0] received [0:63];
    integer received_count;

    always #5 clk = ~clk;

    sha3_shake_stream dut (
        .clk_i(clk), .rst_ni(rst_n), .start_i(start), .mode_i(mode),
        .output_length_i(output_length), .input_byte_i(input_byte),
        .input_valid_i(input_valid), .input_ready_o(input_ready),
        .finalize_i(finalize), .output_byte_o(output_byte),
        .output_valid_o(output_valid), .output_ready_i(output_ready),
        .busy_o(busy), .done_o(done)
    );

    always @(posedge clk)
        if (output_valid && output_ready) begin
            received[received_count] <= output_byte;
            received_count <= received_count + 1;
        end

    task automatic begin_hash(input logic [1:0] selected_mode,
                              input integer length);
        begin
            received_count = 0;
            mode = selected_mode;
            output_length = length;
            start = 1;
            @(posedge clk); #1; start = 0;
        end
    endtask

    task automatic send_byte(input logic [7:0] value);
        begin
            while (!input_ready) @(posedge clk);
            input_byte = value;
            input_valid = 1;
            @(posedge clk); #1; input_valid = 0;
        end
    endtask

    task automatic finish_hash;
        begin
            while (!input_ready) @(posedge clk);
            finalize = 1;
            @(posedge clk); #1; finalize = 0;
            wait(done); @(posedge clk); #1;
        end
    endtask

    task automatic check32(input logic [255:0] expected, input string name);
        integer i;
        begin
            if (received_count != 32) $fatal(1, "%s length %0d", name, received_count);
            for (i=0;i<32;i=i+1)
                if (received[i] !== expected[255-8*i -: 8])
                    $fatal(1, "%s byte %0d got %02x expected %02x",
                           name, i, received[i], expected[255-8*i -: 8]);
            $display("PASS %s", name);
        end
    endtask

    task automatic check64(input logic [511:0] expected, input string name);
        integer i;
        begin
            if (received_count != 64) $fatal(1, "%s length %0d", name, received_count);
            for (i=0;i<64;i=i+1)
                if (received[i] !== expected[511-8*i -: 8])
                    $fatal(1, "%s byte %0d got %02x expected %02x",
                           name, i, received[i], expected[511-8*i -: 8]);
            $display("PASS %s", name);
        end
    endtask

    initial begin
        start=0; input_valid=0; finalize=0; output_ready=1;
        mode=0; output_length=0; input_byte=0;
        repeat(4) @(posedge clk); rst_n=1; @(posedge clk);

        begin_hash(2'd0,32); finish_hash();
        check32(256'ha7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a,
                "SHA3-256(empty)");

        begin_hash(2'd0,32); send_byte("a"); send_byte("b"); send_byte("c"); finish_hash();
        check32(256'h3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532,
                "SHA3-256(abc)");

        begin_hash(2'd1,64); finish_hash();
        check64(512'ha69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26,
                "SHA3-512(empty)");

        begin_hash(2'd2,64); finish_hash();
        check64(512'h7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2,
                "SHAKE128(empty,64)");

        begin_hash(2'd3,64); finish_hash();
        check64(512'h46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be,
                "SHAKE256(empty,64)");

        $display("ALL SHA3/SHAKE TESTS PASSED");
        $finish;
    end
endmodule
