`timescale 1ns/1ps
module tb_mlkem_secure_channel_complete_axi_top;

  logic clk=0,rst=0;always #5 clk=~clk;logic[5:0]fi;logic fdet;logic[7:0]fcode;
  logic[7:0]maw,mar;logic mawv,mawr,mwv,mwr,mbv,mbr,marv,marr,mrv,mrr;
  logic[31:0]mwd,mrd;logic[3:0]mws;logic[1:0]mbp,mrp;
  logic[8:0]aaw,aar;logic aawv,aawr,awv,awr,abv,abr,aarv,aarr,arv,arr;
  logic[31:0]awd,ard;logic[3:0]aws;logic[1:0]abp,arp;
  byte skb[0:1631],ctb[0:767];integer f,i,n;logic[31:0]status,w;
  logic[511:0]got;logic[127:0]got_tag;
  mlkem_secure_channel_complete_axi_top dut(clk,rst,maw,mawv,mawr,mwd,mws,mwv,mwr,mbp,mbv,mbr,
    mar,marv,marr,mrd,mrp,mrv,mrr,aaw,aawv,aawr,awd,aws,awv,awr,abp,abv,abr,
    aar,aarv,aarr,ard,arp,arv,arr,fi,fdet,fcode);
  function automatic[511:0]pack64(input[511:0]x);integer j;begin
    for(j=0;j<64;j=j+1)pack64[8*j+:8]=x[511-8*j-:8];end endfunction
  function automatic[127:0]pack16(input[127:0]x);integer j;begin
    for(j=0;j<16;j=j+1)pack16[8*j+:8]=x[127-8*j-:8];end endfunction
  task automatic mw(input[7:0]x,input[31:0]d);begin @(negedge clk);maw=x;mwd=d;mawv=1;mwv=1;mbr=1;
    while(!(mawr&&mwr))@(posedge clk);@(negedge clk);mawv=0;mwv=0;while(!mbv)@(posedge clk);@(negedge clk);mbr=0;end endtask
  task automatic mr(input[7:0]x,output[31:0]d);begin @(negedge clk);mar=x;marv=1;mrr=1;
    while(!marr)@(posedge clk);@(negedge clk);marv=0;while(!mrv)@(posedge clk);#1;d=mrd;@(negedge clk);mrr=0;end endtask
  task automatic aw(input[8:0]x,input[31:0]d);begin @(negedge clk);aaw=x;awd=d;aawv=1;awv=1;abr=1;
    while(!(aawr&&awr))@(posedge clk);@(negedge clk);aawv=0;awv=0;while(!abv)@(posedge clk);@(negedge clk);abr=0;end endtask
  task automatic ar(input[8:0]x,output[31:0]d);begin @(negedge clk);aar=x;aarv=1;arr=1;
    while(!aarr)@(posedge clk);@(negedge clk);aarv=0;while(!arv)@(posedge clk);#1;d=ard;@(negedge clk);arr=0;end endtask
  task automatic put_data(input[511:0]v);begin for(i=0;i<16;i=i+1)aw(9'h100+4*i,v[32*i+:32]);end endtask
  task automatic put_tag(input[127:0]v);begin for(i=0;i<4;i=i+1)aw(9'h140+4*i,v[32*i+:32]);end endtask
  task automatic get_data(output[511:0]v);begin for(i=0;i<16;i=i+1)begin ar(9'h180+4*i,w);v[32*i+:32]=w;end end endtask
  task automatic get_tag(output[127:0]v);begin for(i=0;i<4;i=i+1)begin ar(9'h1c0+4*i,w);v[32*i+:32]=w;end end endtask

    task automatic check_mlkem_slot(input logic [5:0] test_slot);
    logic [31:0] readback;
    begin
      // ML-KEM AXI-Lite�� REG_SLOT(0x0c)�� ���� ��ȣ ����
      mw(8'h0c, {26'd0, test_slot});

      // ���� �������͸� �ٽ� �о �� �ս� ���� Ȯ��
      mr(8'h0c, readback);

      if (readback[5:0] !== test_slot)
        $fatal(1,
          "ML-KEM slot truncation: wrote %0d, read %0d",
          test_slot, readback[5:0]);

      $display("PASS ML-KEM AXI slot %0d", test_slot);
    end
  endtask

  task automatic wait_packet;begin status=0;while(!status[1])ar(9'h008,status);end endtask
  localparam[511:0]PLAIN=512'h5a6564426f617264204d4c2d4b454d202b2043686143686132302d506f6c79313330352064656d6f000000000000000000000000000000000000000000000000;
  localparam[511:0]ZB_CT=512'hb7b235da3dbbb9ecd92eca9019e9223a368ca0aad5fd167f9c86595d727381cb0ecf98c4fd286c963ffe346c8644bd72386083ca105e9f23cdbc2697877d85fa;
  localparam[127:0]ZB_TAG=128'h0b8552e36371bcd72ab7f0aba138952c;
  localparam[511:0]PC_CT=512'h0132bccb7f7f1112dc451931686edb306441443afcb64a2819d4c0ecbe6f07695eb13090ea943cef95482e6934f6a311410f8f93f4c3d6b9665757e609f77f2a;
  localparam[127:0]PC_TAG=128'h98fe11b3409dd2e381c7711868916dcf;
    integer prof_total;
  integer prof_core;
  integer prof_transcript;
  integer prof_kdf;
  integer prof_install;

  integer prof_ntt;
  integer prof_intt;
  integer prof_basemul;
  integer prof_hash [0:6];

  integer poly_cycles;
  integer hash_cycles;
  integer j;

  logic [1:0] poly_command;
  logic [2:0] hash_command;
  logic poly_running;
  logic hash_running;
  logic profile_running;

  always @(posedge clk) begin
    if (!rst) begin
      prof_total      = 0;
      prof_core       = 0;
      prof_transcript = 0;
      prof_kdf        = 0;
      prof_install    = 0;

      prof_ntt        = 0;
      prof_intt       = 0;
      prof_basemul    = 0;

      poly_cycles     = 0;
      hash_cycles     = 0;

      poly_command    = 0;
      hash_command    = 0;

      poly_running    = 0;
      hash_running    = 0;
      profile_running = 0;

      for (j = 0; j < 7; j = j + 1)
        prof_hash[j] = 0;

    end else begin

      /*
       * ML-KEM AXI START�� ���� launch pulse�� ��ȯ�� �������� ����
       */
      if (dut.core.launch) begin
        prof_total      = 0;
        prof_core       = 0;
        prof_transcript = 0;
        prof_kdf        = 0;
        prof_install    = 0;

        prof_ntt        = 0;
        prof_intt       = 0;
        prof_basemul    = 0;

        poly_cycles     = 0;
        hash_cycles     = 0;

        poly_running    = 0;
        hash_running    = 0;
        profile_running = 1;

        for (j = 0; j < 7; j = j + 1)
          prof_hash[j] = 0;
      end

      if (profile_running) begin
        prof_total = prof_total + 1;

        /*
         * mlkem_secure_channel_fault_protected_indexed_axi_top state:
         * 0 IDLE
         * 1 D_START, 2 D_WAIT
         * 3 T_START, 4 T_WAIT
         * 5 K_START, 6 K_WAIT
         * 7 C_START, 8 C_WAIT
         * 9 REPORT
         */
        case (dut.core.state)
          4'd1, 4'd2:
            prof_core = prof_core + 1;

          4'd3, 4'd4:
            prof_transcript = prof_transcript + 1;

          4'd5, 4'd6:
            prof_kdf = prof_kdf + 1;

          4'd7, 4'd8:
            prof_install = prof_install + 1;

          default: begin
          end
        endcase

        /*
         * K-PKE decrypt �� polynomial accelerator
         */
        if (dut.core.dec.dec.bridge.core_start) begin
          poly_running = 1;
          poly_cycles  = 0;
          poly_command = dut.core.dec.dec.bridge.cmd;
        end

        /*
         * K-PKE re-encryption �� polynomial accelerator
         */
        if (dut.core.dec.enc.bridge.core_start) begin
          poly_running = 1;
          poly_cycles  = 0;
          poly_command = dut.core.dec.enc.bridge.cmd;
        end

        if (poly_running)
          poly_cycles = poly_cycles + 1;

        if (poly_running &&
            (dut.core.dec.dec.bridge.core_done ||
             dut.core.dec.enc.bridge.core_done)) begin

          case (poly_command)
            2'd0: begin
              prof_ntt = prof_ntt + poly_cycles;
              $display("[PROFILE] NTT=%0d cycles",
                       poly_cycles);
            end

            2'd1: begin
              prof_intt = prof_intt + poly_cycles;
              $display("[PROFILE] INTT=%0d cycles",
                       poly_cycles);
            end

            2'd2: begin
              prof_basemul =
                prof_basemul + poly_cycles;
              $display("[PROFILE] BASEMUL=%0d cycles",
                       poly_cycles);
            end
          endcase

          poly_running = 0;
        end

        /*
         * ���� SHA3/SHAKE engine
         */
        if (dut.core.hs_hash) begin
          hash_running = 1;
          hash_cycles  = 0;
          hash_command = dut.core.hcmd_hash;
        end

        if (hash_running)
          hash_cycles = hash_cycles + 1;

        if (hash_running && dut.core.hdone_raw) begin
          prof_hash[hash_command] =
            prof_hash[hash_command] + hash_cycles;

          $display(
            "[PROFILE] HASH command=%0d cycles=%0d",
            hash_command, hash_cycles);

          hash_running = 0;
        end

        /*
         * ��ü ML-KEM �Ϸ�
         */
        if (dut.core.final_done) begin
          $display("");
          $display("========== ML-KEM CYCLE PROFILE ==========");
          $display("TOTAL             = %0d", prof_total);
          $display("CORE DECAP        = %0d", prof_core);
          $display("TRANSCRIPT HASH   = %0d", prof_transcript);
          $display("TRAFFIC KDF       = %0d", prof_kdf);
          $display("SESSION INSTALL   = %0d", prof_install);
          $display("NTT TOTAL         = %0d", prof_ntt);
          $display("INTT TOTAL        = %0d", prof_intt);
          $display("BASEMUL TOTAL     = %0d", prof_basemul);

          $display("H(pk)             = %0d", prof_hash[0]);
          $display("G(m||H(pk))       = %0d", prof_hash[1]);
          $display("J(z||ct)          = %0d", prof_hash[2]);
          $display("MATRIX SHAKE      = %0d", prof_hash[3]);
          $display("NOISE SHAKE       = %0d", prof_hash[4]);
          $display("TRANSCRIPT HASH   = %0d", prof_hash[5]);
          $display("TRAFFIC KDF HASH  = %0d", prof_hash[6]);
          $display("===========================================");

          profile_running = 0;
        end
      end
    end
  end


    integer detail_bridge_load;
  integer detail_bridge_core;
  integer detail_bridge_store;

  integer detail_unpack_ciphertext_sk;
  integer detail_unpack_public_key;
  integer detail_addsub;
  integer detail_from_message;
  integer detail_to_message;
  integer detail_pack_compare;

  logic detail_running;

  always @(posedge clk) begin
    if (!rst) begin
      detail_bridge_load        = 0;
      detail_bridge_core        = 0;
      detail_bridge_store       = 0;
      detail_unpack_ciphertext_sk = 0;
      detail_unpack_public_key  = 0;
      detail_addsub             = 0;
      detail_from_message       = 0;
      detail_to_message         = 0;
      detail_pack_compare       = 0;
      detail_running            = 0;

    end else begin

      if (dut.core.launch) begin
        detail_bridge_load          = 0;
        detail_bridge_core          = 0;
        detail_bridge_store         = 0;
        detail_unpack_ciphertext_sk = 0;
        detail_unpack_public_key    = 0;
        detail_addsub               = 0;
        detail_from_message         = 0;
        detail_to_message           = 0;
        detail_pack_compare         = 0;
        detail_running              = 1;

      end else if (detail_running) begin

        /*
         * mlkem_poly_bridge_controller states:
         * 0      IDLE
         * 1..6   BRAM input load
         * 7..8   arithmetic core start/wait
         * 9..11  BRAM result store
         * 12     DONE
         */

        // K-PKE decrypt bridge
        if ((dut.core.dec.dec.bridge.state >= 4'd1) &&
            (dut.core.dec.dec.bridge.state <= 4'd6))
          detail_bridge_load = detail_bridge_load + 1;

        if ((dut.core.dec.dec.bridge.state == 4'd7) ||
            (dut.core.dec.dec.bridge.state == 4'd8))
          detail_bridge_core = detail_bridge_core + 1;

        if ((dut.core.dec.dec.bridge.state >= 4'd9) &&
            (dut.core.dec.dec.bridge.state <= 4'd11))
          detail_bridge_store = detail_bridge_store + 1;

        // K-PKE re-encryption bridge
        if ((dut.core.dec.enc.bridge.state >= 4'd1) &&
            (dut.core.dec.enc.bridge.state <= 4'd6))
          detail_bridge_load = detail_bridge_load + 1;

        if ((dut.core.dec.enc.bridge.state == 4'd7) ||
            (dut.core.dec.enc.bridge.state == 4'd8))
          detail_bridge_core = detail_bridge_core + 1;

        if ((dut.core.dec.enc.bridge.state >= 4'd9) &&
            (dut.core.dec.enc.bridge.state <= 4'd11))
          detail_bridge_store = detail_bridge_store + 1;

        // Ciphertext�� K-PKE secret-key unpack
        if (dut.core.dec.dec.unpack.state != 0)
          detail_unpack_ciphertext_sk =
            detail_unpack_ciphertext_sk + 1;

        // Public key �� rho/H(pk)/z ����
        if (dut.core.dec.unpack_pk.state != 0)
          detail_unpack_public_key =
            detail_unpack_public_key + 1;

        // Polynomial add/sub
        if (dut.core.dec.dec.addsub.state != 0)
          detail_addsub = detail_addsub + 1;

        if (dut.core.dec.enc.addsub.state != 0)
          detail_addsub = detail_addsub + 1;

        // 32-byte message�� polynomial�� ��ȯ
        if (dut.core.dec.enc.frommsg.state != 0)
          detail_from_message = detail_from_message + 1;

        // Polynomial�� 32-byte message�� ����
        if (dut.core.dec.dec.tomsg.state != 0)
          detail_to_message = detail_to_message + 1;

        // ���ȣȭ ��� ���� �� ciphertext ��
        if (dut.core.dec.enc.compare.state != 0)
          detail_pack_compare = detail_pack_compare + 1;

        if (dut.core.final_done) begin
          $display("");
          $display("======= ML-KEM DATA-MOVEMENT PROFILE =======");
          $display("BRIDGE INPUT LOAD       = %0d",
                   detail_bridge_load);
          $display("BRIDGE CORE WAIT        = %0d",
                   detail_bridge_core);
          $display("BRIDGE RESULT STORE     = %0d",
                   detail_bridge_store);
          $display("CT/SK UNPACK            = %0d",
                   detail_unpack_ciphertext_sk);
          $display("PUBLIC-KEY UNPACK       = %0d",
                   detail_unpack_public_key);
          $display("POLY ADD/SUB            = %0d",
                   detail_addsub);
          $display("MESSAGE -> POLY         = %0d",
                   detail_from_message);
          $display("POLY -> MESSAGE         = %0d",
                   detail_to_message);
          $display("PACK/COMPARE            = %0d",
                   detail_pack_compare);
          $display("=============================================");

          detail_running = 0;
        end
      end
    end
  end
  initial begin maw=0;mar=0;mawv=0;mwv=0;mbr=0;marv=0;mrr=0;mwd=0;mws=15;

    aaw=0;aar=0;aawv=0;awv=0;abr=0;aarv=0;arr=0;awd=0;aws=15;fi=0;
    f=$fopen(
  "C:/soc_fpga/zed_pqc/src/zedboard-pqc-secure/outputs/golden_reference/secret_key.bin",
  "rb");
if(!f)$fatal(1,"sk");
n=$fread(skb,f);
$fclose(f);

f=$fopen(
  "C:/soc_fpga/zed_pqc/src/zedboard-pqc-secure/outputs/golden_reference/kem_ciphertext.bin",
  "rb");
if(!f)$fatal(1,"ct");
n=$fread(ctb,f);
$fclose(f);

    repeat(4)@(posedge clk);rst=1;repeat(2)@(posedge clk);
    check_mlkem_slot(6'd0);
    check_mlkem_slot(6'd3);
    check_mlkem_slot(6'd4);   // �ٽ�: ���� ���׸� ���⼭ 0���� ����
    check_mlkem_slot(6'd15);
    check_mlkem_slot(6'd16);
    check_mlkem_slot(6'd31);
    check_mlkem_slot(6'd63);
    mw(8'h20,0);mw(8'h24,0);for(i=0;i<408;i=i+1)mw(8'h28,{skb[4*i+3],skb[4*i+2],skb[4*i+1],skb[4*i]});
    mw(8'h20,1);mw(8'h24,0);for(i=0;i<192;i=i+1)mw(8'h28,{ctb[4*i+3],ctb[4*i+2],ctb[4*i+1],ctb[4*i]});
    mw(8'h0c,0);mw(8'h10,32'h01020304);mw(8'h04,32'h100);mw(8'h04,1);
    wait(dut.core.final_done);repeat(3)@(posedge clk);mr(8'h08,status);
    if(!status[2]||status[3]||fdet)$fatal(1,"protected Decaps failed %h",status);
    $display("PASS dual-AXI ML-KEM load, Decaps and atomic session install");
    aw(9'h00c,0);aw(9'h010,40);put_data(pack64(PLAIN));aw(9'h004,1);wait_packet();
    if(!status[2]||status[3])$fatal(1,"encrypt status %h",status);get_data(got);
    if(got!==pack64(ZB_CT))$fatal(1,"encrypt data");get_tag(got_tag);
    if(got_tag!==pack16(ZB_TAG))$fatal(1,"encrypt tag");
    $display("PASS PS-facing AXI traffic encryption uses installed ZB-to-PC session");
    aw(9'h004,32'h100);aw(9'h014,0);aw(9'h018,0);put_data(pack64(PC_CT));put_tag(pack16(PC_TAG));
    aw(9'h004,3);wait_packet();if(!status[2]||status[3])$fatal(1,"decrypt status %h",status);get_data(got);
    if(got!==pack64(PLAIN))$fatal(1,"decrypt data");
    $display("PASS PS-facing AXI traffic authenticated decryption");
    aw(9'h004,32'h100);aw(9'h004,3);wait_packet();if(status[2]||!status[3])$fatal(1,"replay status %h",status);
    get_data(got);if(got!==0)$fatal(1,"replay plaintext leak");
    $display("PASS PS-facing AXI replay rejection remains fail-closed");
    $display("ALL COMPLETE DUAL-AXI SECURE CHANNEL TESTS PASSED");$finish;
  end
  initial begin #300000000;$fatal(1,"complete AXI timeout");end
endmodule
