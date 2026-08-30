`timescale 1ns/1ps

module tb_mlkem_cycle_counter;

    localparam [7:0] REG_CONTROL = 8'h04;
    localparam [7:0] REG_CYCLES  = 8'h2C;

    logic clk = 0;
    logic resetn = 0;

    logic [7:0]  awaddr = 0;
    logic        awvalid = 0;
    logic        awready;
    logic [31:0] wdata = 0;
    logic [3:0]  wstrb = 0;
    logic        wvalid = 0;
    logic        wready;
    logic [1:0]  bresp;
    logic        bvalid;
    logic        bready = 0;

    logic [7:0]  araddr = 0;
    logic        arvalid = 0;
    logic        arready;
    logic [31:0] rdata;
    logic [1:0]  rresp;
    logic        rvalid;
    logic        rready = 0;

    logic        decap_start;
    logic [5:0]  decap_slot;
    logic [31:0] decap_session_id;
    logic        decap_busy = 0;
    logic        decap_done = 0;
    logic        decap_fail = 0;

    logic [31:0] sk_rdata;
    logic [31:0] ct_rdata;
    logic [15:0] poly_rdata;

    logic [31:0] read_value;
    integer reference_cycles = 0;

    // 50 MHz
    always #10 clk = ~clk;

    mlkem_decaps_axi_lite_frontend #(
        .C_S_AXI_ADDR_WIDTH(8),
        .SLOT_WIDTH(6)
    ) dut (
        .s_axi_aclk(clk),
        .s_axi_aresetn(resetn),

        .s_axi_awaddr(awaddr),
        .s_axi_awvalid(awvalid),
        .s_axi_awready(awready),

        .s_axi_wdata(wdata),
        .s_axi_wstrb(wstrb),
        .s_axi_wvalid(wvalid),
        .s_axi_wready(wready),

        .s_axi_bresp(bresp),
        .s_axi_bvalid(bvalid),
        .s_axi_bready(bready),

        .s_axi_araddr(araddr),
        .s_axi_arvalid(arvalid),
        .s_axi_arready(arready),

        .s_axi_rdata(rdata),
        .s_axi_rresp(rresp),
        .s_axi_rvalid(rvalid),
        .s_axi_rready(rready),

        .decap_start_o(decap_start),
        .decap_slot_o(decap_slot),
        .decap_session_id_o(decap_session_id),
        .decap_busy_i(decap_busy),
        .decap_done_i(decap_done),
        .decap_fail_i(decap_fail),

        .sk_we_i(1'b0),
        .sk_addr_i(9'd0),
        .sk_wdata_i(32'd0),
        .sk_rdata_o(sk_rdata),

        .ct_we_i(1'b0),
        .ct_addr_i(8'd0),
        .ct_wdata_i(32'd0),
        .ct_rdata_o(ct_rdata),

        .poly_we_i(1'b0),
        .poly_addr_i(12'd0),
        .poly_wdata_i(16'd0),
        .poly_rdata_o(poly_rdata)
    );

    task automatic axi_write(
        input [7:0] address,
        input [31:0] data
    );
        begin
            @(negedge clk);
            awaddr  = address;
            awvalid = 1'b1;
            wdata   = data;
            wstrb   = 4'hF;
            wvalid  = 1'b1;

            do @(posedge clk);
            while (!(awready && wready));

            @(negedge clk);
            awvalid = 1'b0;
            wvalid  = 1'b0;

            while (!bvalid)
                @(posedge clk);

            @(negedge clk);
            bready = 1'b1;

            @(posedge clk);
            @(negedge clk);
            bready = 1'b0;
        end
    endtask

    task automatic axi_read(
        input [7:0] address,
        output [31:0] data
    );
        begin
            @(negedge clk);
            araddr  = address;
            arvalid = 1'b1;

            do @(posedge clk);
            while (!arready);

            @(negedge clk);
            arvalid = 1'b0;

            while (!rvalid)
                @(posedge clk);

            data = rdata;

            @(negedge clk);
            rready = 1'b1;

            @(posedge clk);
            @(negedge clk);
            rready = 1'b0;
        end
    endtask

    // RTL 카운터와 비교할 독립 reference counter
    always @(posedge clk) begin
        if (!resetn)
            reference_cycles = 0;
        else if (decap_start)
            reference_cycles = 0;
        else if (dut.cycle_running)
            reference_cycles = reference_cycles + 1;
    end

    task automatic finish_request(
        input integer running_clocks,
        input bit failed
    );
        begin
            wait (dut.cycle_running === 1'b1);

            repeat (running_clocks)
                @(posedge clk);

            @(negedge clk);
            decap_fail = failed;
            decap_done = 1'b1;

            @(posedge clk);
            @(negedge clk);
            decap_done = 1'b0;
            decap_fail = 1'b0;

            wait (dut.cycle_running === 1'b0);
        end
    endtask

    initial begin
        // Reset
        repeat (5)
            @(posedge clk);

        @(negedge clk);
        resetn = 1'b1;

        repeat (2)
            @(posedge clk);

        // 1. Reset 값 확인
        axi_read(REG_CYCLES, read_value);

        if (read_value !== 32'd0)
            $fatal(1,
                "Reset value=%0d, expected 0",
                read_value);

        $display("[PASS] reset value is zero");

        // 2. 첫 번째 정상 요청
        fork
            axi_write(REG_CONTROL, 32'h0000_0001);
            finish_request(100, 1'b0);
        join

        axi_read(REG_CYCLES, read_value);

        if ((read_value !== reference_cycles) ||
            (read_value == 0))
            $fatal(1,
                "First result=%0d, reference=%0d",
                read_value, reference_cycles);

        $display(
            "[PASS] first request cycles=%0d",
            read_value);

        // 3. DONE 이후 값 유지 확인
        repeat (10)
            @(posedge clk);

        axi_read(REG_CYCLES, read_value);

        if (read_value !== reference_cycles)
            $fatal(1,
                "Cycle result changed after DONE");

        $display(
            "[PASS] result remains stable after DONE");

        // 4. 다음 START에서 재시작 및 실패 종료 측정
        fork
            axi_write(REG_CONTROL, 32'h0000_0001);
            finish_request(17, 1'b1);
        join

        axi_read(REG_CYCLES, read_value);

        if ((read_value !== reference_cycles) ||
            (read_value == 0))
            $fatal(1,
                "Failed-request result=%0d, reference=%0d",
                read_value, reference_cycles);

        $display(
            "[PASS] failed request cycles=%0d",
            read_value);

        $display(
            "ALL ML-KEM CYCLE COUNTER TESTS PASSED");

        $finish;
    end

endmodule