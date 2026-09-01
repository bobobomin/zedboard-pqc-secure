`timescale 1ns/1ps

/* DMA-free AXI4-Lite loader/control front-end for the PL Decaps engine. */
module mlkem_decaps_axi_lite_frontend #(
    parameter integer C_S_AXI_ADDR_WIDTH=8,
    parameter integer SLOT_WIDTH=2
)(
    input logic s_axi_aclk,input logic s_axi_aresetn,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_awaddr,input logic s_axi_awvalid,
    output logic s_axi_awready,input logic[31:0]s_axi_wdata,input logic[3:0]s_axi_wstrb,
    input logic s_axi_wvalid,output logic s_axi_wready,output logic[1:0]s_axi_bresp,
    output logic s_axi_bvalid,input logic s_axi_bready,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_araddr,input logic s_axi_arvalid,
    output logic s_axi_arready,output logic[31:0]s_axi_rdata,output logic[1:0]s_axi_rresp,
    output logic s_axi_rvalid,input logic s_axi_rready,
    output logic decap_start_o,output logic[SLOT_WIDTH-1:0]decap_slot_o,
    output logic[31:0]decap_session_id_o,input logic decap_busy_i,
    input logic decap_done_i,input logic decap_fail_i,
    input logic sk_we_i,input logic[8:0]sk_addr_i,input logic[31:0]sk_wdata_i,
    output logic[31:0]sk_rdata_o,input logic ct_we_i,input logic[7:0]ct_addr_i,
    input logic[31:0]ct_wdata_i,output logic[31:0]ct_rdata_o,
    input logic poly_we_i,input logic[11:0]poly_addr_i,input logic[15:0]poly_wdata_i,
    output logic[15:0]poly_rdata_o
);
    localparam[7:0]REG_VERSION=0,REG_CONTROL=4,REG_STATUS=8,REG_SLOT=12,
        REG_SESSION=16,REG_MEM_REGION=32,REG_MEM_ADDR=36,REG_MEM_DATA=40;
    localparam[1:0]RESP_OKAY=2'b00,RESP_SLVERR=2'b10;
    logic aw_hold,w_hold;logic[C_S_AXI_ADDR_WIDTH-1:0]awaddr_q;logic[31:0]wdata_q;
    logic[3:0]wstrb_q;
    logic[1:0]region;logic[11:0]mem_addr,mem_access_addr;logic mem_valid,mem_we,mem_ready;
    logic[31:0]mem_rdata;logic read_mem_pending,done_latched,fail_latched;

    /* Byte lanes with WSTRB=0 keep their previous value. */
    function automatic logic[31:0]merge_bytes(input logic[31:0]old_value,
                                              input logic[31:0]new_value,
                                              input logic[3:0]strobe);
        logic[31:0]merged;
        merged=old_value;
        for(int lane=0;lane<4;lane++)
            if(strobe[lane])merged[8*lane+:8]=new_value[8*lane+:8];
        return merged;
    endfunction

    /* Reset arrives already synchronised from the top, so it is used as an
       asynchronous reset here like everywhere else in this clock domain, and it
       holds the AXI channels closed instead of swallowing a transfer. */
    assign s_axi_awready=s_axi_aresetn&&!aw_hold&&!s_axi_bvalid;
    assign s_axi_wready=s_axi_aresetn&&!w_hold&&!s_axi_bvalid;
    assign s_axi_arready=s_axi_aresetn&&!s_axi_rvalid&&!read_mem_pending;
    assign s_axi_rresp=RESP_OKAY;

    mlkem_decaps_memory u_mem(.clk_i(s_axi_aclk),.host_valid_i(mem_valid),
        .host_we_i(mem_we),.host_region_i(region),.host_addr_i(mem_access_addr),
        .host_wdata_i(wdata_q),.host_rdata_o(mem_rdata),.host_ready_o(mem_ready),
        .sk_we_i(sk_we_i),.sk_addr_i(sk_addr_i),.sk_wdata_i(sk_wdata_i),.sk_rdata_o(sk_rdata_o),
        .ct_we_i(ct_we_i),.ct_addr_i(ct_addr_i),.ct_wdata_i(ct_wdata_i),.ct_rdata_o(ct_rdata_o),
        .poly_we_i(poly_we_i),.poly_addr_i(poly_addr_i),.poly_wdata_i(poly_wdata_i),
        .poly_rdata_o(poly_rdata_o));

    always_ff @(posedge s_axi_aclk or negedge s_axi_aresetn)begin
        if(!s_axi_aresetn)begin aw_hold<=0;w_hold<=0;s_axi_bvalid<=0;s_axi_bresp<=RESP_OKAY;
            s_axi_rvalid<=0;s_axi_rdata<=0;awaddr_q<=0;wdata_q<=0;wstrb_q<=0;
            region<=0;mem_addr<=0;mem_access_addr<=0;mem_valid<=0;mem_we<=0;
            read_mem_pending<=0;decap_start_o<=0;decap_slot_o<=0;
            decap_session_id_o<=0;done_latched<=0;fail_latched<=0;end
        else begin
            mem_valid<=0;mem_we<=0;decap_start_o<=0;
            if(decap_done_i)begin done_latched<=1;fail_latched<=decap_fail_i;end
            if(s_axi_awvalid&&s_axi_awready)begin awaddr_q<=s_axi_awaddr;aw_hold<=1;end
            if(s_axi_wvalid&&s_axi_wready)begin wdata_q<=s_axi_wdata;wstrb_q<=s_axi_wstrb;w_hold<=1;end
            if(aw_hold&&w_hold&&!s_axi_bvalid)begin
                s_axi_bresp<=RESP_OKAY;
                case(awaddr_q)
                    REG_CONTROL:begin
                        if(wstrb_q[1]&&wdata_q[8])begin done_latched<=0;fail_latched<=0;end
                        if(wstrb_q[0]&&wdata_q[0]&&!decap_busy_i)decap_start_o<=1;
                    end
                    REG_SLOT:if(wstrb_q[0])decap_slot_o<=wdata_q[SLOT_WIDTH-1:0];
                    REG_SESSION:decap_session_id_o<=merge_bytes(decap_session_id_o,wdata_q,wstrb_q);
                    REG_MEM_REGION:if(wstrb_q[0])region<=wdata_q[1:0];
                    REG_MEM_ADDR:begin
                        if(wstrb_q[0])mem_addr[7:0]<=wdata_q[7:0];
                        if(wstrb_q[1])mem_addr[11:8]<=wdata_q[11:8];
                    end
                    /* The storage macros carry no byte enables, so the data window takes
                       whole words only; a partial strobe is reported instead of guessed. */
                    REG_MEM_DATA:begin
                        if(wstrb_q==4'hF)begin mem_access_addr<=mem_addr;mem_valid<=1;
                            mem_we<=1;mem_addr<=mem_addr+12'd1;end
                        else if(wstrb_q!=4'h0)s_axi_bresp<=RESP_SLVERR;
                    end

                    default:begin end
                endcase
                aw_hold<=0;w_hold<=0;s_axi_bvalid<=1;
            end else if(s_axi_bvalid&&s_axi_bready)s_axi_bvalid<=0;

            if(s_axi_arvalid&&s_axi_arready)begin
                case(s_axi_araddr)
                    REG_VERSION:begin s_axi_rdata<=32'h0002_0000;s_axi_rvalid<=1;end
                    REG_STATUS:begin s_axi_rdata<={28'd0,fail_latched,done_latched,
                                                   decap_busy_i,read_mem_pending};s_axi_rvalid<=1;end
                    REG_SLOT:begin s_axi_rdata<={{(32-SLOT_WIDTH){1'b0}},decap_slot_o};s_axi_rvalid<=1;end
                    REG_SESSION:begin s_axi_rdata<=decap_session_id_o;s_axi_rvalid<=1;end
                    REG_MEM_REGION:begin s_axi_rdata<={30'd0,region};s_axi_rvalid<=1;end
                    REG_MEM_ADDR:begin s_axi_rdata<={20'd0,mem_addr};s_axi_rvalid<=1;end
                    REG_MEM_DATA:begin mem_access_addr<=mem_addr;mem_valid<=1;
                        mem_we<=0;read_mem_pending<=1;end
                    default:begin s_axi_rdata<=0;s_axi_rvalid<=1;end
                endcase
            end
            if(read_mem_pending&&mem_ready)begin s_axi_rdata<=mem_rdata;
                s_axi_rvalid<=1;read_mem_pending<=0;mem_addr<=mem_addr+12'd1;end
            if(s_axi_rvalid&&s_axi_rready)s_axi_rvalid<=0;
        end
    end
endmodule
