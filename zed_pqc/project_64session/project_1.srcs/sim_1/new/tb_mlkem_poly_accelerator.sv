`timescale 1ns/1ps
module tb_mlkem_poly_accelerator;
    logic clk=0,rst_n=0,start,host_we;
    logic [1:0] command,host_bank;
    logic [7:0] host_addr;
    logic signed [15:0] host_wdata,host_rdata;
    logic busy,done;
    integer i;
    always #5 clk=~clk;

    mlkem_poly_accelerator dut(.*,
        .clk_i(clk),.rst_ni(rst_n),.start_i(start),.command_i(command),
        .busy_o(busy),.done_o(done),.host_we_i(host_we),.host_bank_i(host_bank),
        .host_addr_i(host_addr),.host_wdata_i(host_wdata),.host_rdata_o(host_rdata));

    task automatic write_coeff(input [1:0] bank,input integer address,input integer value);
        begin host_bank=bank; host_addr=address; host_wdata=value; host_we=1;
            @(posedge clk); #1; host_we=0; end
    endtask
    task automatic run_command(input [1:0] cmd);
        begin command=cmd; start=1; @(posedge clk); #1; start=0;
            wait(done); @(posedge clk); #1; end
    endtask
    task automatic check(input [1:0] bank,input integer address,
                         input integer expected,input string name);
        begin host_bank=bank;host_addr=address;@(posedge clk);#1;
            if ($signed(host_rdata)!==expected)
                $fatal(1,"%s[%0d] got %0d expected %0d",name,address,$signed(host_rdata),expected);
        end
    endtask

    initial begin
        start=0;host_we=0;command=0;host_bank=0;host_addr=0;host_wdata=0;
        repeat(4) @(posedge clk);rst_n=1;@(posedge clk);
        for(i=0;i<256;i=i+1) begin
            write_coeff(0,i,(i*17+3)%3329);
            write_coeff(1,i,(i*29+5)%3329);
        end
        run_command(0);
        check(0,0,-736,"NTT"); check(0,1,-3651,"NTT");
        check(0,2,-1652,"NTT"); check(0,3,-5349,"NTT");
        check(0,17,160,"NTT"); check(0,31,-4024,"NTT");
        check(0,63,1959,"NTT"); check(0,64,-2803,"NTT");
        check(0,95,-3966,"NTT"); check(0,127,-3023,"NTT");
        check(0,128,-2018,"NTT"); check(0,191,-397,"NTT");
        check(0,223,2924,"NTT"); check(0,253,5213,"NTT");
        check(0,254,1670,"NTT"); check(0,255,4619,"NTT");
        $display("PASS ML-KEM forward NTT reference samples");

        run_command(1);
        check(0,0,197,"INTT"); check(0,1,-906,"INTT");
        check(0,2,1320,"INTT"); check(0,3,217,"INTT");
        check(0,17,1420,"INTT"); check(0,31,-706,"INTT");
        check(0,63,617,"INTT"); check(0,64,-486,"INTT");
        check(0,95,-1389,"INTT"); check(0,127,-66,"INTT");
        check(0,128,-1169,"INTT"); check(0,191,-749,"INTT");
        check(0,223,574,"INTT"); check(0,253,774,"INTT");
        check(0,254,-329,"INTT"); check(0,255,-1432,"INTT");
        $display("PASS ML-KEM inverse NTT reference samples");

        for(i=0;i<256;i=i+1) write_coeff(0,i,(i*17+3)%3329);
        run_command(2);
        check(2,0,-1277,"BaseMul"); check(2,1,848,"BaseMul");
        check(2,2,-524,"BaseMul"); check(2,3,-1620,"BaseMul");
        check(2,17,2346,"BaseMul"); check(2,31,-1456,"BaseMul");
        check(2,63,2942,"BaseMul"); check(2,64,480,"BaseMul");
        check(2,95,-1992,"BaseMul"); check(2,127,-2942,"BaseMul");
        check(2,128,1466,"BaseMul"); check(2,191,452,"BaseMul");
        check(2,223,-1862,"BaseMul"); check(2,253,-101,"BaseMul");
        check(2,254,67,"BaseMul"); check(2,255,-192,"BaseMul");
        $display("PASS ML-KEM BaseMul reference samples");
        $display("ALL ML-KEM POLYNOMIAL TESTS PASSED");$finish;
    end
endmodule
