`timescale 1ns/1ps
module tb_mlkem_poly_addsub_streaming;
    logic clk=0,rst_n=0,start=0,subtract=0;
    logic busy,done,we;logic[11:0]addr;logic[15:0]wdata,rdata;
    logic[15:0]mem[0:3071];integer i,cycles,expected;

    always #5 clk=~clk;
    always_ff @(posedge clk)begin
        if(we)mem[addr]<=wdata;
        rdata<=mem[addr];
    end

    mlkem_poly_addsub_controller dut(
        .clk_i(clk),.rst_ni(rst_n),.start_i(start),.subtract_i(subtract),
        .src_a_slot_i(4'd1),.src_b_slot_i(4'd2),.dst_slot_i(4'd3),
        .busy_o(busy),.done_o(done),.poly_we_o(we),.poly_addr_o(addr),
        .poly_wdata_o(wdata),.poly_rdata_i(rdata));

    function automatic integer canonical(input integer value);
        begin
            canonical=value%3329;
            if(canonical<0)canonical=canonical+3329;
        end
    endfunction

    task automatic run_and_check(input logic do_subtract);
        begin
            @(negedge clk);subtract=do_subtract;start=1;
            @(negedge clk);start=0;cycles=0;
            while(!done)begin
                @(negedge clk);cycles=cycles+1;
                if(cycles>780)$fatal(1,"controller timeout");
            end
            for(i=0;i<256;i=i+1)begin
                expected=canonical(do_subtract?
                    ($signed(mem[256+i])-$signed(mem[512+i])):
                    ($signed(mem[256+i])+$signed(mem[512+i])));
                if(mem[768+i]!==expected[15:0])
                    $fatal(1,"coeff %0d got %0d expected %0d",i,mem[768+i],expected);
            end
            if(cycles>775)$fatal(1,"cycle count %0d exceeds streaming target",cycles);
            $display("STREAMING ADD/SUB subtract=%0d cycles=%0d PASS",do_subtract,cycles);
            @(negedge clk);
        end
    endtask

    initial begin
        rdata=0;
        for(i=0;i<3072;i=i+1)mem[i]=0;
        for(i=0;i<256;i=i+1)begin
            mem[256+i]=(i*17)%3329;
            mem[512+i]=(i*29+7)%3329;
        end
        repeat(3)@(posedge clk);rst_n=1;
        run_and_check(1'b0);
        run_and_check(1'b1);
        $display("ALL STREAMING POLY ADD/SUB TESTS PASSED");
        $finish;
    end
endmodule
