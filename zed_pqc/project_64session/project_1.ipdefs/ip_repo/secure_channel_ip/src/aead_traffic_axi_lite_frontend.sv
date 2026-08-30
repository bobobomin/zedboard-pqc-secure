`timescale 1ns/1ps

/*
 * AXI4-Lite traffic adapter for an already-instantiated four-session AEAD
 * arbiter.  Session creation stays inside the ML-KEM protected top; this
 * block only submits packet encrypt/decrypt requests and returns results.
 */
module aead_traffic_axi_lite_frontend #(
    parameter integer C_S_AXI_ADDR_WIDTH = 9
)(
    input logic clk_i,input logic rst_ni,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_awaddr,input logic s_axi_awvalid,
    output logic s_axi_awready,input logic[31:0]s_axi_wdata,input logic[3:0]s_axi_wstrb,
    input logic s_axi_wvalid,output logic s_axi_wready,output logic[1:0]s_axi_bresp,
    output logic s_axi_bvalid,input logic s_axi_bready,
    input logic[C_S_AXI_ADDR_WIDTH-1:0]s_axi_araddr,input logic s_axi_arvalid,
    output logic s_axi_arready,output logic[31:0]s_axi_rdata,output logic[1:0]s_axi_rresp,
    output logic s_axi_rvalid,input logic s_axi_rready,
    input logic fault_detected_i,input logic[7:0]fault_code_i,
    output logic[3:0]req_valid_o,input logic[3:0]req_ready_i,
    output logic[3:0]req_decrypt_o,output logic[31:0]req_data_len_o,
    output logic[255:0]req_counter_o,output logic[2047:0]req_data_o,
    output logic[511:0]req_tag_o,input logic[3:0]rsp_valid_i,
    output logic[3:0]rsp_ready_o,input logic[3:0]rsp_auth_ok_i,
    input logic[3:0]rsp_error_i,input logic[255:0]rsp_counter_i,
    input logic[2047:0]rsp_data_i,input logic[511:0]rsp_tag_i
);
    localparam[8:0]REG_VERSION=9'h000,REG_CONTROL=9'h004,REG_STATUS=9'h008,
      REG_SLOT=9'h00c,REG_LENGTH=9'h010,REG_COUNTER_LO=9'h014,
      REG_COUNTER_HI=9'h018,REG_RSP_COUNTER_LO=9'h01c,
      REG_RSP_COUNTER_HI=9'h020,REG_FAULT=9'h024,
      REG_INPUT_DATA=9'h100,REG_INPUT_TAG=9'h140,
      REG_OUTPUT_DATA=9'h180,REG_OUTPUT_TAG=9'h1c0;
    logic aw_hold,w_hold,write_commit;logic[C_S_AXI_ADDR_WIDTH-1:0]awaddr_q;
    logic[31:0]wdata_q;logic[3:0]wstrb_q;logic[1:0]slot_reg,slot_q;
    logic[7:0]length_reg,length_q;logic[63:0]counter_reg,counter_q;
    logic decrypt_q,pending,inflight,done_q,auth_q,error_q;
    logic[511:0]data_q;logic[127:0]tag_q;logic[63:0]rsp_counter_q;
    logic[511:0]rsp_data_q;logic[127:0]rsp_tag_q;
    logic[31:0]input_data[0:15];logic[31:0]input_tag[0:3];
    logic[31:0]read_mux;integer i;
    function automatic[31:0]merge(input[31:0]oldv,input[31:0]newv,input[3:0]strb);
      integer b;begin merge=oldv;for(b=0;b<4;b=b+1)if(strb[b])merge[8*b+:8]=newv[8*b+:8];end
    endfunction
    assign s_axi_awready=!aw_hold&&!s_axi_bvalid;
    assign s_axi_wready=!w_hold&&!s_axi_bvalid;assign s_axi_bresp=0;
    assign s_axi_arready=!s_axi_rvalid;assign s_axi_rresp=0;
    always_comb begin
      req_valid_o=0;req_decrypt_o=0;req_data_len_o=0;req_counter_o=0;req_data_o=0;req_tag_o=0;
      if(pending)begin req_valid_o[slot_q]=1;req_decrypt_o[slot_q]=decrypt_q;
        req_data_len_o[8*slot_q+:8]=length_q;req_counter_o[64*slot_q+:64]=counter_q;
        req_data_o[512*slot_q+:512]=data_q;req_tag_o[128*slot_q+:128]=tag_q;end
      rsp_ready_o=0;if(inflight)rsp_ready_o[slot_q]=1;
    end
    always_comb begin
      read_mux=0;
      case(s_axi_araddr[8:0])
        REG_VERSION:read_mux=32'h0003_0000;
        REG_STATUS:begin read_mux[0]=inflight;read_mux[1]=done_q;read_mux[2]=auth_q;
          read_mux[3]=error_q;read_mux[4]=pending;read_mux[5]=fault_detected_i;end
        REG_SLOT:read_mux={30'd0,slot_reg};REG_LENGTH:read_mux={24'd0,length_reg};
        REG_COUNTER_LO:read_mux=counter_reg[31:0];REG_COUNTER_HI:read_mux=counter_reg[63:32];
        REG_RSP_COUNTER_LO:read_mux=rsp_counter_q[31:0];
        REG_RSP_COUNTER_HI:read_mux=rsp_counter_q[63:32];
        REG_FAULT:read_mux={23'd0,fault_detected_i,fault_code_i};
        default:begin
          for(i=0;i<16;i=i+1)begin
            if(s_axi_araddr[8:0]==REG_INPUT_DATA+4*i)read_mux=input_data[i];
            if(s_axi_araddr[8:0]==REG_OUTPUT_DATA+4*i)read_mux=rsp_data_q[32*i+:32];end
          for(i=0;i<4;i=i+1)begin
            if(s_axi_araddr[8:0]==REG_INPUT_TAG+4*i)read_mux=input_tag[i];
            if(s_axi_araddr[8:0]==REG_OUTPUT_TAG+4*i)read_mux=rsp_tag_q[32*i+:32];end
        end
      endcase
    end
    always_ff @(posedge clk_i)begin
      if(!rst_ni)begin aw_hold<=0;w_hold<=0;write_commit<=0;s_axi_bvalid<=0;
        s_axi_rvalid<=0;s_axi_rdata<=0;slot_reg<=0;length_reg<=0;counter_reg<=0;
        slot_q<=0;length_q<=0;counter_q<=0;decrypt_q<=0;pending<=0;inflight<=0;
        done_q<=0;auth_q<=0;error_q<=0;data_q<=0;tag_q<=0;rsp_counter_q<=0;
        rsp_data_q<=0;rsp_tag_q<=0;for(i=0;i<16;i=i+1)input_data[i]<=0;
        for(i=0;i<4;i=i+1)input_tag[i]<=0;
      end else begin
        write_commit<=0;
        if(s_axi_awvalid&&s_axi_awready)begin awaddr_q<=s_axi_awaddr;aw_hold<=1;end
        if(s_axi_wvalid&&s_axi_wready)begin wdata_q<=s_axi_wdata;wstrb_q<=s_axi_wstrb;w_hold<=1;end
        if(aw_hold&&w_hold&&!s_axi_bvalid)begin write_commit<=1;aw_hold<=0;w_hold<=0;s_axi_bvalid<=1;end
        else if(s_axi_bvalid&&s_axi_bready)s_axi_bvalid<=0;
        if(s_axi_arvalid&&s_axi_arready)begin s_axi_rdata<=read_mux;s_axi_rvalid<=1;end
        else if(s_axi_rvalid&&s_axi_rready)s_axi_rvalid<=0;
        if(pending&&req_ready_i[slot_q])pending<=0;
        if(inflight&&rsp_valid_i[slot_q]&&rsp_ready_o[slot_q])begin
          rsp_counter_q<=rsp_counter_i[64*slot_q+:64];rsp_data_q<=rsp_data_i[512*slot_q+:512];
          rsp_tag_q<=rsp_tag_i[128*slot_q+:128];auth_q<=rsp_auth_ok_i[slot_q];
          error_q<=rsp_error_i[slot_q];done_q<=1;inflight<=0;end
        if(write_commit)begin
          case(awaddr_q[8:0])
            REG_CONTROL:begin
              if(wstrb_q[1]&&wdata_q[8])done_q<=0;
              if(wstrb_q[0]&&wdata_q[0]&&!pending&&!inflight)begin
                slot_q<=slot_reg;length_q<=length_reg;counter_q<=counter_reg;decrypt_q<=wdata_q[1];
                for(i=0;i<16;i=i+1)data_q[32*i+:32]<=input_data[i];
                for(i=0;i<4;i=i+1)tag_q[32*i+:32]<=input_tag[i];
                pending<=1;inflight<=1;done_q<=0;auth_q<=0;error_q<=0;end
            end
            REG_SLOT:slot_reg<=merge({30'd0,slot_reg},wdata_q,wstrb_q);
            REG_LENGTH:length_reg<=merge({24'd0,length_reg},wdata_q,wstrb_q);
            REG_COUNTER_LO:counter_reg[31:0]<=merge(counter_reg[31:0],wdata_q,wstrb_q);
            REG_COUNTER_HI:counter_reg[63:32]<=merge(counter_reg[63:32],wdata_q,wstrb_q);
            default:begin
              for(i=0;i<16;i=i+1)if(awaddr_q[8:0]==REG_INPUT_DATA+4*i)
                input_data[i]<=merge(input_data[i],wdata_q,wstrb_q);
              for(i=0;i<4;i=i+1)if(awaddr_q[8:0]==REG_INPUT_TAG+4*i)
                input_tag[i]<=merge(input_tag[i],wdata_q,wstrb_q);
            end
          endcase
        end
      end
    end
endmodule
