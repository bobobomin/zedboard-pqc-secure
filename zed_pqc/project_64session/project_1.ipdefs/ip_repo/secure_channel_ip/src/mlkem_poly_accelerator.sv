`timescale 1ns/1ps

/*
 * ML-KEM polynomial arithmetic kernel (q=3329, n=256).
 * command 0: forward NTT, A -> A
 * command 1: inverse NTT-to-Montgomery, A -> A
 * command 2: base multiplication, A * B -> R
 *
 * The host port is intentionally small so it can be exposed through an
 * AXI-Lite coefficient window during bring-up and changed to DMA later.
 *
 * Every bank exists twice.  set_i names the half the arithmetic uses; the host
 * port always addresses the other one, so the bridge can store the previous
 * result and load the next operands while a command is running.  The two
 * halves are separate arrays rather than one array with a wider address,
 * because the arithmetic needs both ports of its own half.
 */
module mlkem_poly_accelerator (
    input  logic               clk_i,
    input  logic               rst_ni,
    input  logic               start_i,
    input  logic [1:0]         command_i,
    input  logic               set_i,
    output logic               busy_o,
    output logic               done_o,
    input  logic               host_we_i,
    input  logic [1:0]         host_bank_i,
    input  logic [7:0]         host_addr_i,
    input  logic signed [15:0] host_wdata_i,
    output logic signed [15:0] host_rdata_o
);
    localparam logic [1:0] CMD_NTT=2'd0, CMD_INTT=2'd1, CMD_BASEMUL=2'd2;
    typedef enum logic [4:0] {IDLE,
                              NTT_RUN, NTT_DRAIN,
                              INTT_SCALE_RUN, INTT_SCALE_DRAIN,
                              INTT_RUN, INTT_DRAIN,
                              BASEMUL_RUN, BASEMUL_DRAIN} state_t;
    state_t state;

    /* bank_a is split by address bit-parity.  Inside one NTT/INTT layer the
     * paired addresses i and i+span differ in exactly one bit, so their
     * parities are always opposite; BaseMul's 2i/2i+1 pair differs in bit 0
     * and splits the same way.  Two 128-word halves, each with a dedicated
     * read port and a dedicated write port, therefore serve the two reads and
     * two writes a pipelined butterfly needs without ever colliding. */
    (* ram_style="block" *) logic signed [15:0] bank_a0s0[0:127],bank_a0s1[0:127];
    (* ram_style="block" *) logic signed [15:0] bank_a1s0[0:127],bank_a1s1[0:127];
    (* ram_style="block" *) logic signed [15:0] bank_bs0[0:255],bank_bs1[0:255];
    (* ram_style="block" *) logic signed [15:0] bank_rs0[0:255],bank_rs1[0:255];
    logic signed [15:0] zetas[0:127];
    integer layer, span, block_start, butterfly, zeta_index;
    logic [2:0] drain;
    /* Arithmetic-side request channel.  Reads and writes happen in the same
     * cycle, so each presents its own pair to the parity shim. */
    logic a_we0,a_we1,r_we0,r_we1;
    logic [7:0] a_raddr0,a_raddr1,a_waddr0,a_waddr1;
    logic [7:0] b_addr0,b_addr1,r_addr0,r_addr1;
    logic signed [15:0] a_wdin0,a_wdin1,r_din0,r_din1;
    logic signed [15:0] a_dout0,a_dout1,b_dout0,b_dout1;
    logic a_rsel,a_rsel_q,a_wsel,a_w0_we,a_w1_we;
    logic [6:0] a_r0_addr,a_r1_addr,a_w0_addr,a_w1_addr;
    logic signed [15:0] a_w0_din,a_w1_din,a_r0_dout,a_r1_dout;
    /* Host-side request channel, one access per cycle into the other half. */
    logic ha_we,hb_we,hr_we,ha_sel,ha_sel_q,ha_w0_we,ha_w1_we,set_q;
    logic [6:0] ha_idx;
    logic signed [15:0] a0s0_dout,a0s1_dout,a1s0_dout,a1s1_dout;
    logic signed [15:0] bs0_dout0,bs0_dout1,bs1_dout0,bs1_dout1;
    logic signed [15:0] rs0_dout0,rs1_dout0;
    logic signed [15:0] bm_a0_reg,bm_a1_reg,bm_b0_reg,bm_b1_reg;
    /* Break every Montgomery product across clock boundaries so the BaseMul
     * BRAM-to-BRAM path holds one multiply per stage, as NTT/INTT already do.
     * The eight stages run as a pipeline: one coefficient pair is issued and
     * one retires per clock, so no register may be reused by a later stage of
     * the same pair.  Values produced early and consumed late get their own
     * delay chains instead. */
    logic signed [31:0] basemul_prod11_reg, basemul_prod00_reg;
    logic signed [31:0] basemul_prod01_reg, basemul_prod10_reg;
    /* The reduction needs the raw product one stage after the multiplier
     * register is formed, and by then the product registers hold the next
     * pair. */
    logic signed [31:0] basemul_prod11_d1, basemul_prod00_d1;
    logic signed [31:0] basemul_prod01_d1, basemul_prod10_d1;
    logic signed [15:0] basemul_mult11_reg, basemul_mult00_reg;
    logic signed [15:0] basemul_mult01_reg, basemul_mult10_reg;
    logic signed [15:0] basemul_p11_reg, basemul_p00_reg;
    logic signed [15:0] basemul_p01_reg, basemul_p10_reg;
    /* p00/p01/p10 are reduced three stages before the zeta path finishes. */
    logic signed [15:0] basemul_p00_d1, basemul_p00_d2, basemul_p00_d3;
    logic signed [15:0] basemul_p01_d1, basemul_p01_d2, basemul_p01_d3;
    logic signed [15:0] basemul_p10_d1, basemul_p10_d2, basemul_p10_d3;
    /* The zeta multiply keeps its own product/multiplier registers; the p11
     * pair is occupied by the following coefficient pairs. */
    logic signed [31:0] basemul_zprod_reg, basemul_zprod_d1;
    logic signed [15:0] basemul_zmult_reg;
    logic signed [15:0] basemul_p11z_reg;
    /* The zeta ROM read and its conditional negation are registered at the
     * multiply stage so the zeta multiply drives the multiplier from registers
     * only, then delayed to meet its pair three stages later. */
    logic signed [15:0] basemul_zeta_reg, basemul_zeta_d1, basemul_zeta_d2;
    /* Pair index and valid bit follow the data through all eight stages: the
     * write of pair i lands eight cycles after its read address is issued. */
    logic [6:0] bm_ptr, bm_idx_d[1:8];
    logic bm_vld_d[1:8];

    /* NTT/INTT arithmetic pipeline.  One Montgomery reduction contains three
     * dependent multiplies (coefficient product and the two reduction
     * multiplies).  Keep one multiply per clock stage so the BRAM-to-BRAM
     * butterfly path can meet the ZedBoard clock constraint. */
    logic signed [15:0] butterfly_a_reg, butterfly_a_d1, butterfly_a_d2;
    logic signed [15:0] intt_sum_reg, intt_diff_reg, intt_sum_d1, intt_sum_d2;
    logic signed [31:0] fq_product_reg, fq_product_d1;
    logic signed [15:0] mont_multiplier_reg;
    logic signed [15:0] fq_result_reg;
    logic signed [31:0] barrett_accum_reg, barrett_temp_reg;
    logic signed [15:0] barrett_result_reg;
    /* The zeta ROM is read at the issue stage, one cycle ahead of the NTT
     * multiply and two ahead of the INTT one, which also takes the ROM lookup
     * out of the multiplier path.  Index and valid follow the data so the
     * write of butterfly i lands four (NTT) or five (INTT) cycles after its
     * read address is issued. */
    logic signed [15:0] zeta_d1, zeta_d2;
    logic [7:0] bf_d[1:5];
    logic vld_d[1:5];

    /* The scalar helpers that chained three multiplies in one expression were
     * removed with the BaseMul split; every multiply now sits in its own FSM
     * stage.  Reintroducing them would restore the failing path. */

    initial begin
        zetas[0]=-1044; zetas[1]=-758; zetas[2]=-359; zetas[3]=-1517;
        zetas[4]=1493; zetas[5]=1422; zetas[6]=287; zetas[7]=202;
        zetas[8]=-171; zetas[9]=622; zetas[10]=1577; zetas[11]=182;
        zetas[12]=962; zetas[13]=-1202; zetas[14]=-1474; zetas[15]=1468;
        zetas[16]=573; zetas[17]=-1325; zetas[18]=264; zetas[19]=383;
        zetas[20]=-829; zetas[21]=1458; zetas[22]=-1602; zetas[23]=-130;
        zetas[24]=-681; zetas[25]=1017; zetas[26]=732; zetas[27]=608;
        zetas[28]=-1542; zetas[29]=411; zetas[30]=-205; zetas[31]=-1571;
        zetas[32]=1223; zetas[33]=652; zetas[34]=-552; zetas[35]=1015;
        zetas[36]=-1293; zetas[37]=1491; zetas[38]=-282; zetas[39]=-1544;
        zetas[40]=516; zetas[41]=-8; zetas[42]=-320; zetas[43]=-666;
        zetas[44]=-1618; zetas[45]=-1162; zetas[46]=126; zetas[47]=1469;
        zetas[48]=-853; zetas[49]=-90; zetas[50]=-271; zetas[51]=830;
        zetas[52]=107; zetas[53]=-1421; zetas[54]=-247; zetas[55]=-951;
        zetas[56]=-398; zetas[57]=961; zetas[58]=-1508; zetas[59]=-725;
        zetas[60]=448; zetas[61]=-1065; zetas[62]=677; zetas[63]=-1275;
        zetas[64]=-1103; zetas[65]=430; zetas[66]=555; zetas[67]=843;
        zetas[68]=-1251; zetas[69]=871; zetas[70]=1550; zetas[71]=105;
        zetas[72]=422; zetas[73]=587; zetas[74]=177; zetas[75]=-235;
        zetas[76]=-291; zetas[77]=-460; zetas[78]=1574; zetas[79]=1653;
        zetas[80]=-246; zetas[81]=778; zetas[82]=1159; zetas[83]=-147;
        zetas[84]=-777; zetas[85]=1483; zetas[86]=-602; zetas[87]=1119;
        zetas[88]=-1590; zetas[89]=644; zetas[90]=-872; zetas[91]=349;
        zetas[92]=418; zetas[93]=329; zetas[94]=-156; zetas[95]=-75;
        zetas[96]=817; zetas[97]=1097; zetas[98]=603; zetas[99]=610;
        zetas[100]=1322; zetas[101]=-1285; zetas[102]=-1465; zetas[103]=384;
        zetas[104]=-1215; zetas[105]=-136; zetas[106]=1218; zetas[107]=-1335;
        zetas[108]=-874; zetas[109]=220; zetas[110]=-1187; zetas[111]=-1659;
        zetas[112]=-1185; zetas[113]=-1530; zetas[114]=-1278; zetas[115]=794;
        zetas[116]=-1510; zetas[117]=-854; zetas[118]=-870; zetas[119]=478;
        zetas[120]=-108; zetas[121]=-308; zetas[122]=996; zetas[123]=991;
        zetas[124]=958; zetas[125]=-1460; zetas[126]=1522; zetas[127]=1628;
    end

    /* Parity routing for the arithmetic channel.  a_raddr0/a_raddr1 and
     * a_waddr0/a_waddr1 are request pairs; the parity of the first address
     * decides which half serves which, and the read selector delayed by the
     * read latency puts the two words back on a_dout0/a_dout1.  The host makes
     * one access per cycle, so it presents the same index to both halves and
     * only enables the write on the matching parity. */
    always_comb begin
        a_rsel=^a_raddr0;
        a_r0_addr=a_rsel?a_raddr1[7:1]:a_raddr0[7:1];
        a_r1_addr=a_rsel?a_raddr0[7:1]:a_raddr1[7:1];
        a_wsel=^a_waddr0;
        a_w0_addr=a_wsel?a_waddr1[7:1]:a_waddr0[7:1];
        a_w1_addr=a_wsel?a_waddr0[7:1]:a_waddr1[7:1];
        a_w0_din=a_wsel?a_wdin1:a_wdin0;
        a_w1_din=a_wsel?a_wdin0:a_wdin1;
        a_w0_we=a_wsel?a_we1:a_we0;
        a_w1_we=a_wsel?a_we0:a_we1;
        ha_sel=^host_addr_i;ha_idx=host_addr_i[7:1];
        ha_w0_we=ha_we&&!ha_sel;ha_w1_we=ha_we&&ha_sel;
        a_r0_dout=set_q?a0s1_dout:a0s0_dout;
        a_r1_dout=set_q?a1s1_dout:a1s0_dout;
        a_dout0=a_rsel_q?a_r1_dout:a_r0_dout;
        a_dout1=a_rsel_q?a_r0_dout:a_r1_dout;
        b_dout0=set_q?bs1_dout0:bs0_dout0;
        b_dout1=set_q?bs1_dout1:bs0_dout1;
    end
    /* One read port and one write port per array infers simple dual-port RAM.
     * set_i picks which channel owns which half; the host always gets the one
     * the arithmetic is not using. */
    always_ff @(posedge clk_i) begin
        a_rsel_q<=a_rsel;ha_sel_q<=ha_sel;set_q<=set_i;
    end
    always_ff @(posedge clk_i) begin
        a0s0_dout<=bank_a0s0[set_i?ha_idx:a_r0_addr];
        if(set_i?ha_w0_we:a_w0_we)
            bank_a0s0[set_i?ha_idx:a_w0_addr]<=set_i?host_wdata_i:a_w0_din;
    end
    always_ff @(posedge clk_i) begin
        a0s1_dout<=bank_a0s1[set_i?a_r0_addr:ha_idx];
        if(set_i?a_w0_we:ha_w0_we)
            bank_a0s1[set_i?a_w0_addr:ha_idx]<=set_i?a_w0_din:host_wdata_i;
    end
    always_ff @(posedge clk_i) begin
        a1s0_dout<=bank_a1s0[set_i?ha_idx:a_r1_addr];
        if(set_i?ha_w1_we:a_w1_we)
            bank_a1s0[set_i?ha_idx:a_w1_addr]<=set_i?host_wdata_i:a_w1_din;
    end
    always_ff @(posedge clk_i) begin
        a1s1_dout<=bank_a1s1[set_i?a_r1_addr:ha_idx];
        if(set_i?a_w1_we:ha_w1_we)
            bank_a1s1[set_i?a_w1_addr:ha_idx]<=set_i?a_w1_din:host_wdata_i;
    end
    /* BaseMul reads bank_b on both ports and never writes it, so the host
     * shares port 0 of the half it owns. */
    always_ff @(posedge clk_i) begin
        bs0_dout0<=bank_bs0[set_i?host_addr_i:b_addr0];
        if(set_i&&hb_we)bank_bs0[host_addr_i]<=host_wdata_i;
    end
    always_ff @(posedge clk_i) begin
        bs0_dout1<=bank_bs0[b_addr1];
    end
    always_ff @(posedge clk_i) begin
        bs1_dout0<=bank_bs1[set_i?b_addr0:host_addr_i];
        if(!set_i&&hb_we)bank_bs1[host_addr_i]<=host_wdata_i;
    end
    always_ff @(posedge clk_i) begin
        bs1_dout1<=bank_bs1[b_addr1];
    end
    /* BaseMul writes bank_r on both ports and never reads it, so the host
     * shares port 0 of the half it owns. */
    always_ff @(posedge clk_i) begin
        rs0_dout0<=bank_rs0[set_i?host_addr_i:r_addr0];
        if(set_i?hr_we:r_we0)
            bank_rs0[set_i?host_addr_i:r_addr0]<=set_i?host_wdata_i:r_din0;
    end
    always_ff @(posedge clk_i) begin
        if(!set_i&&r_we1)bank_rs0[r_addr1]<=r_din1;
    end
    always_ff @(posedge clk_i) begin
        rs1_dout0<=bank_rs1[set_i?r_addr0:host_addr_i];
        if(set_i?r_we0:hr_we)
            bank_rs1[set_i?r_addr0:host_addr_i]<=set_i?r_din0:host_wdata_i;
    end
    always_ff @(posedge clk_i) begin
        if(set_i&&r_we1)bank_rs1[r_addr1]<=r_din1;
    end

    always_comb begin
        a_we0=0;a_we1=0;r_we0=0;r_we1=0;
        a_raddr0=0;a_raddr1=0;a_waddr0=0;a_waddr1=0;
        b_addr0=0;b_addr1=0;r_addr0=0;r_addr1=0;
        a_wdin0=0;a_wdin1=0;r_din0=0;r_din1=0;
        /* The host half is never the half under computation, so host writes no
         * longer have to wait for the core to be idle. */
        ha_we=host_we_i&&host_bank_i==2'd0;
        hb_we=host_we_i&&host_bank_i==2'd1;
        hr_we=host_we_i&&host_bank_i>=2'd2;
        case(state)
            NTT_RUN,INTT_RUN:begin
                a_raddr0=butterfly;a_raddr1=butterfly+span;
            end
            INTT_SCALE_RUN:a_raddr0=butterfly;
            BASEMUL_RUN:begin
                a_raddr0=2*bm_ptr;a_raddr1=2*bm_ptr+1;
                b_addr0=2*bm_ptr;b_addr1=2*bm_ptr+1;
            end
            default:begin end
        endcase
        /* Butterflies retire while later ones are still being read, so the
         * coefficient write ports are driven from the delayed index and valid
         * bit instead of from a write state.  span is only advanced after the
         * layer has drained, so it is still the retiring butterfly's span. */
        if(vld_d[4]&&(state==INTT_SCALE_RUN||state==INTT_SCALE_DRAIN))begin
            a_waddr0=bf_d[4];a_we0=1;
            a_wdin0=fq_result_reg;
        end
        if(vld_d[4]&&(state==NTT_RUN||state==NTT_DRAIN))begin
            a_waddr0=bf_d[4];a_waddr1=bf_d[4]+span;a_we0=1;a_we1=1;
            a_wdin0=butterfly_a_d2+fq_result_reg;
            a_wdin1=butterfly_a_d2-fq_result_reg;
        end
        if(vld_d[5]&&(state==INTT_RUN||state==INTT_DRAIN))begin
            a_waddr0=bf_d[5];a_waddr1=bf_d[5]+span;a_we0=1;a_we1=1;
            a_wdin0=barrett_result_reg;
            a_wdin1=fq_result_reg;
        end
        /* Results retire while later pairs are still being read, so the result
         * port is driven from the delayed valid bit and not from a state. */
        if(bm_vld_d[8])begin
            r_addr0=2*bm_idx_d[8];r_addr1=2*bm_idx_d[8]+1;r_we0=1;r_we1=1;
            r_din0=basemul_p11z_reg+basemul_p00_d3;
            r_din1=basemul_p01_d3+basemul_p10_d3;
        end
        case(host_bank_i)
            0:host_rdata_o=ha_sel_q?(set_q?a1s0_dout:a1s1_dout)
                                   :(set_q?a0s0_dout:a0s1_dout);
            1:host_rdata_o=set_q?bs0_dout0:bs1_dout0;
            default:host_rdata_o=set_q?rs0_dout0:rs1_dout0;
        endcase
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state<=IDLE; busy_o<=0; done_o<=0; layer<=0; span<=0;
            block_start<=0; butterfly<=0; zeta_index<=0; bm_ptr<=0;
            drain<=0; zeta_d1<=0; zeta_d2<=0;
            butterfly_a_d1<=0; butterfly_a_d2<=0; fq_product_d1<=0;
            intt_sum_d1<=0; intt_sum_d2<=0;
            for(int k=1;k<=5;k++)begin bf_d[k]<=0;vld_d[k]<=0;end
            basemul_prod11_reg<=0;basemul_prod00_reg<=0;
            basemul_prod01_reg<=0;basemul_prod10_reg<=0;
            basemul_prod11_d1<=0;basemul_prod00_d1<=0;
            basemul_prod01_d1<=0;basemul_prod10_d1<=0;
            basemul_mult11_reg<=0;basemul_mult00_reg<=0;
            basemul_mult01_reg<=0;basemul_mult10_reg<=0;
            basemul_p11_reg<=0;basemul_p00_reg<=0;
            basemul_p01_reg<=0;basemul_p10_reg<=0;
            basemul_p00_d1<=0;basemul_p00_d2<=0;basemul_p00_d3<=0;
            basemul_p01_d1<=0;basemul_p01_d2<=0;basemul_p01_d3<=0;
            basemul_p10_d1<=0;basemul_p10_d2<=0;basemul_p10_d3<=0;
            basemul_zprod_reg<=0;basemul_zprod_d1<=0;basemul_zmult_reg<=0;
            basemul_p11z_reg<=0;
            basemul_zeta_reg<=0;basemul_zeta_d1<=0;basemul_zeta_d2<=0;
            bm_a0_reg<=0;bm_a1_reg<=0;bm_b0_reg<=0;bm_b1_reg<=0;
            for(int k=1;k<=8;k++)begin bm_idx_d[k]<=0;bm_vld_d[k]<=0;end
            butterfly_a_reg<=0;intt_sum_reg<=0;intt_diff_reg<=0;
            fq_product_reg<=0;mont_multiplier_reg<=0;fq_result_reg<=0;
            barrett_accum_reg<=0;barrett_temp_reg<=0;barrett_result_reg<=0;
        end else begin
            done_o <= 0;
            case (state)
                IDLE: if (start_i) begin
                    busy_o<=1;
                    for(int k=1;k<=5;k++)vld_d[k]<=0;
                    case (command_i)
                        CMD_NTT: begin layer<=1; span<=128; block_start<=0;
                            butterfly<=0; zeta_index<=1; state<=NTT_RUN; end
                        CMD_INTT: begin butterfly<=0; state<=INTT_SCALE_RUN; end
                        default: begin bm_ptr<=0; state<=BASEMUL_RUN; end
                    endcase
                end

                /* One butterfly issued per clock.  The four register stages
                   are the old READ/MUL/MONT/REDUCE boundaries, unchanged, so
                   per-stage logic depth is the same; only the sequencing
                   changes.  Addresses inside a layer never repeat, so the
                   reads of butterfly i+4 cannot collide with the writes of
                   butterfly i.  Layers are separated by NTT_DRAIN, which
                   stops issuing for the pipeline depth so the last writes
                   land before the next layer reads them. */
                NTT_RUN,NTT_DRAIN: begin
                    butterfly_a_reg<=a_dout0;
                    fq_product_reg<=a_dout1*zeta_d1;
                    mont_multiplier_reg<=fq_product_reg[15:0]*16'd62209;
                    fq_product_d1<=fq_product_reg;
                    butterfly_a_d1<=butterfly_a_reg;
                    fq_result_reg<=(fq_product_d1-
                        mont_multiplier_reg*32'sd3329)>>>16;
                    butterfly_a_d2<=butterfly_a_d1;
                    zeta_d1<=zetas[zeta_index];
                    bf_d[1]<=butterfly;vld_d[1]<=(state==NTT_RUN);
                    for(int k=2;k<=4;k++)begin
                        bf_d[k]<=bf_d[k-1];vld_d[k]<=vld_d[k-1];
                    end
                    if (state==NTT_RUN) begin
                        if (butterfly == block_start+span-1) begin
                            if (block_start+2*span >= 256) begin
                                drain<=3; state<=NTT_DRAIN;
                            end else begin
                                block_start<=block_start+2*span;
                                butterfly<=block_start+2*span;
                                zeta_index<=zeta_index+1;
                            end
                        end else butterfly<=butterfly+1;
                    end else if (drain==0) begin
                        if (layer == 7) begin state<=IDLE; busy_o<=0; done_o<=1; end
                        else begin layer<=layer+1; span<=span>>1; block_start<=0;
                            butterfly<=0; zeta_index<=zeta_index+1;state<=NTT_RUN; end
                    end else drain<=drain-3'd1;
                end

                /* The n^-1 scale pass is the same four register stages as a
                   forward butterfly with the zeta multiply replaced by the
                   constant 1441, so it reuses the butterfly pipeline's
                   registers and index chain.  Read j and write j-4 are always
                   different addresses, and the drain lets the last writes land
                   before the butterfly stage reads them back. */
                INTT_SCALE_RUN,INTT_SCALE_DRAIN: begin
                    fq_product_reg<=a_dout0*16'sd1441;
                    mont_multiplier_reg<=fq_product_reg[15:0]*16'd62209;
                    fq_product_d1<=fq_product_reg;
                    fq_result_reg<=(fq_product_d1-
                        mont_multiplier_reg*32'sd3329)>>>16;
                    bf_d[1]<=butterfly;vld_d[1]<=(state==INTT_SCALE_RUN);
                    for(int k=2;k<=4;k++)begin
                        bf_d[k]<=bf_d[k-1];vld_d[k]<=vld_d[k-1];
                    end
                    if (state==INTT_SCALE_RUN) begin
                        if (butterfly==255) begin drain<=3; state<=INTT_SCALE_DRAIN; end
                        else butterfly<=butterfly+1;
                    end else if (drain==0) begin
                        layer<=7; span<=2; block_start<=0;
                        butterfly<=0; zeta_index<=127;
                        /* The scale pass leaves its trailing bubbles in the
                           chain; clear them so no stale valid reaches the
                           butterfly stage's write port. */
                        for(int k=1;k<=5;k++)vld_d[k]<=0;
                        state<=INTT_RUN;
                    end else drain<=drain-3'd1;
                end

                /* Same transformation as NTT, one stage deeper because the
                   inverse butterfly adds the sum/difference stage ahead of the
                   multiply.  The Barrett branch carries its own sum copies so
                   the reduction still meets its coefficient at the write. */
                INTT_RUN,INTT_DRAIN: begin
                    intt_sum_reg<=a_dout0+a_dout1;
                    intt_diff_reg<=a_dout1-a_dout0;
                    fq_product_reg<=intt_diff_reg*zeta_d2;
                    barrett_accum_reg<=32'sd20159*intt_sum_reg+32'sd33554432;
                    intt_sum_d1<=intt_sum_reg;
                    mont_multiplier_reg<=fq_product_reg[15:0]*16'd62209;
                    barrett_temp_reg<=barrett_accum_reg>>>26;
                    fq_product_d1<=fq_product_reg;
                    intt_sum_d2<=intt_sum_d1;
                    fq_result_reg<=(fq_product_d1-
                        mont_multiplier_reg*32'sd3329)>>>16;
                    barrett_result_reg<=intt_sum_d2-
                        barrett_temp_reg*32'sd3329;
                    zeta_d1<=zetas[zeta_index];zeta_d2<=zeta_d1;
                    bf_d[1]<=butterfly;vld_d[1]<=(state==INTT_RUN);
                    for(int k=2;k<=5;k++)begin
                        bf_d[k]<=bf_d[k-1];vld_d[k]<=vld_d[k-1];
                    end
                    if (state==INTT_RUN) begin
                        if (butterfly == block_start+span-1) begin
                            if (block_start+2*span >= 256) begin
                                drain<=4; state<=INTT_DRAIN;
                            end else begin block_start<=block_start+2*span;
                                butterfly<=block_start+2*span;
                                zeta_index<=zeta_index-1; end
                        end else butterfly<=butterfly+1;
                    end else if (drain==0) begin
                        if (layer==1) begin state<=IDLE; busy_o<=0; done_o<=1; end
                        else begin layer<=layer-1; span<=span<<1; block_start<=0;
                            butterfly<=0; zeta_index<=(1<<(layer-1))-1;state<=INTT_RUN; end
                    end else drain<=drain-3'd1;
                end

                /* Every stage advances on every clock in both states; the
                   coefficient RAM output still gets its own latch stage so the
                   block RAM read delay and the DSP entry never share a clock.
                   BASEMUL_RUN issues one read per cycle for 128 pairs,
                   BASEMUL_DRAIN lets the eight in-flight pairs retire. */
                BASEMUL_RUN,BASEMUL_DRAIN:begin
                    bm_a0_reg<=a_dout0;bm_a1_reg<=a_dout1;
                    bm_b0_reg<=b_dout0;bm_b1_reg<=b_dout1;
                    basemul_prod11_reg<=bm_a1_reg*bm_b1_reg;
                    basemul_prod00_reg<=bm_a0_reg*bm_b0_reg;
                    basemul_prod01_reg<=bm_a0_reg*bm_b1_reg;
                    basemul_prod10_reg<=bm_a1_reg*bm_b0_reg;
                    basemul_zeta_reg<=bm_idx_d[2][0]
                        ? -zetas[64+(bm_idx_d[2]>>1)]:zetas[64+(bm_idx_d[2]>>1)];
                    basemul_mult11_reg<=basemul_prod11_reg[15:0]*16'd62209;
                    basemul_mult00_reg<=basemul_prod00_reg[15:0]*16'd62209;
                    basemul_mult01_reg<=basemul_prod01_reg[15:0]*16'd62209;
                    basemul_mult10_reg<=basemul_prod10_reg[15:0]*16'd62209;
                    basemul_prod11_d1<=basemul_prod11_reg;
                    basemul_prod00_d1<=basemul_prod00_reg;
                    basemul_prod01_d1<=basemul_prod01_reg;
                    basemul_prod10_d1<=basemul_prod10_reg;
                    basemul_zeta_d1<=basemul_zeta_reg;
                    basemul_p11_reg<=(basemul_prod11_d1-
                        basemul_mult11_reg*32'sd3329)>>>16;
                    basemul_p00_reg<=(basemul_prod00_d1-
                        basemul_mult00_reg*32'sd3329)>>>16;
                    basemul_p01_reg<=(basemul_prod01_d1-
                        basemul_mult01_reg*32'sd3329)>>>16;
                    basemul_p10_reg<=(basemul_prod10_d1-
                        basemul_mult10_reg*32'sd3329)>>>16;
                    basemul_zeta_d2<=basemul_zeta_d1;
                    basemul_zprod_reg<=basemul_p11_reg*basemul_zeta_d2;
                    basemul_p00_d1<=basemul_p00_reg;basemul_p00_d2<=basemul_p00_d1;
                    basemul_p00_d3<=basemul_p00_d2;
                    basemul_p01_d1<=basemul_p01_reg;basemul_p01_d2<=basemul_p01_d1;
                    basemul_p01_d3<=basemul_p01_d2;
                    basemul_p10_d1<=basemul_p10_reg;basemul_p10_d2<=basemul_p10_d1;
                    basemul_p10_d3<=basemul_p10_d2;
                    basemul_zmult_reg<=basemul_zprod_reg[15:0]*16'd62209;
                    basemul_zprod_d1<=basemul_zprod_reg;
                    basemul_p11z_reg<=(basemul_zprod_d1-
                        basemul_zmult_reg*32'sd3329)>>>16;
                    bm_idx_d[1]<=bm_ptr;bm_vld_d[1]<=(state==BASEMUL_RUN);
                    for(int k=2;k<=8;k++)begin
                        bm_idx_d[k]<=bm_idx_d[k-1];bm_vld_d[k]<=bm_vld_d[k-1];
                    end
                    if(state==BASEMUL_RUN)begin
                        if(bm_ptr==127)state<=BASEMUL_DRAIN;
                        else bm_ptr<=bm_ptr+1;
                    end else if(bm_vld_d[8]&&bm_idx_d[8]==7'd127) begin
                        state<=IDLE; busy_o<=0; done_o<=1;
                    end
                end
                default: state<=IDLE;
            endcase
        end
    end
endmodule
