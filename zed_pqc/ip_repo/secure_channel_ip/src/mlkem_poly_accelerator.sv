`timescale 1ns/1ps

/*
 * ML-KEM polynomial arithmetic kernel (q=3329, n=256).
 * command 0: forward NTT, A -> A
 * command 1: inverse NTT-to-Montgomery, A -> A
 * command 2: base multiplication, A * B -> R
 *
 * The host port is intentionally small so it can be exposed through an
 * AXI-Lite coefficient window during bring-up and changed to DMA later.
 */
module mlkem_poly_accelerator (
    input  logic               clk_i,
    input  logic               rst_ni,
    input  logic               start_i,
    input  logic [1:0]         command_i,
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
                              NTT_READ, NTT_MUL, NTT_MONT,
                              NTT_REDUCE, NTT_WRITE,
                              INTT_SCALE_READ, INTT_SCALE_MUL,
                              INTT_SCALE_MONT, INTT_SCALE_REDUCE,
                              INTT_SCALE_WRITE,
                              INTT_READ, INTT_PREP, INTT_MUL,
                              INTT_MONT, INTT_REDUCE, INTT_WRITE,
                              BASEMUL_READ, BASEMUL_MUL,
                              BASEMUL_ZETA, BASEMUL_WRITE} state_t;
    state_t state;

    (* ram_style="block" *) logic signed [15:0] bank_a[0:255];
    (* ram_style="block" *) logic signed [15:0] bank_b[0:255];
    (* ram_style="block" *) logic signed [15:0] bank_r[0:255];
    logic signed [15:0] zetas[0:127];
    integer layer, span, block_start, butterfly, zeta_index, pair_index;
    logic a_we0,a_we1,b_we0,b_we1,r_we0,r_we1;
    logic [7:0] a_addr0,a_addr1,b_addr0,b_addr1,r_addr0,r_addr1;
    logic signed [15:0] a_din0,a_din1,b_din0,b_din1,r_din0,r_din1;
    logic signed [15:0] a_dout0,a_dout1,b_dout0,b_dout1,r_dout0,r_dout1;
    /* Break the nested Montgomery products across clock boundaries so the
     * BaseMul BRAM-to-BRAM path never contains two fqmul chains in series. */
    logic signed [15:0] basemul_p11_reg, basemul_p00_reg;
    logic signed [15:0] basemul_p01_reg, basemul_p10_reg;
    logic signed [15:0] basemul_p11z_reg;

    /* NTT/INTT arithmetic pipeline.  A combinational fqmul contains three
     * dependent multiplies (coefficient product and the two Montgomery
     * reduction multiplies).  Keep one multiply per clock stage so the
     * BRAM-to-BRAM butterfly path can meet the ZedBoard clock constraint. */
    logic signed [15:0] butterfly_a_reg;
    logic signed [15:0] intt_sum_reg, intt_diff_reg;
    logic signed [31:0] fq_product_reg;
    logic signed [15:0] mont_multiplier_reg;
    logic signed [15:0] fq_result_reg;
    logic signed [31:0] barrett_accum_reg, barrett_temp_reg;
    logic signed [15:0] barrett_result_reg;

    function automatic logic signed [15:0] montgomery_reduce(
        input logic signed [31:0] value);
        logic [15:0] product_low;
        logic signed [15:0] multiplier;
        logic signed [31:0] reduced;
        begin
            product_low = value[15:0] * 16'd62209;
            multiplier = $signed(product_low);
            reduced = value - multiplier * 32'sd3329;
            montgomery_reduce = reduced >>> 16;
        end
    endfunction

    function automatic logic signed [15:0] fqmul(
        input logic signed [15:0] left,
        input logic signed [15:0] right);
        logic signed [31:0] product;
        begin product = left * right; fqmul = montgomery_reduce(product); end
    endfunction

    function automatic logic signed [15:0] barrett_reduce(
        input logic signed [15:0] value);
        logic signed [31:0] temp;
        begin
            temp = (32'sd20159 * value + 32'sd33554432) >>> 26;
            barrett_reduce = value - temp * 32'sd3329;
        end
    endfunction

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

    /* Two explicit synchronous ports per coefficient bank infer block RAM. */
    always_ff @(posedge clk_i) begin
        if(a_we0)bank_a[a_addr0]<=a_din0;
        a_dout0<=bank_a[a_addr0];
    end
    always_ff @(posedge clk_i) begin
        if(a_we1)bank_a[a_addr1]<=a_din1;
        a_dout1<=bank_a[a_addr1];
    end
    always_ff @(posedge clk_i) begin
        if(b_we0)bank_b[b_addr0]<=b_din0;
        b_dout0<=bank_b[b_addr0];
    end
    always_ff @(posedge clk_i) begin
        if(b_we1)bank_b[b_addr1]<=b_din1;
        b_dout1<=bank_b[b_addr1];
    end
    always_ff @(posedge clk_i) begin
        if(r_we0)bank_r[r_addr0]<=r_din0;
        r_dout0<=bank_r[r_addr0];
    end
    always_ff @(posedge clk_i) begin
        if(r_we1)bank_r[r_addr1]<=r_din1;
        r_dout1<=bank_r[r_addr1];
    end

    always_comb begin
        a_we0=0;a_we1=0;b_we0=0;b_we1=0;r_we0=0;r_we1=0;
        a_addr0=host_addr_i;a_addr1=0;b_addr0=host_addr_i;b_addr1=0;
        r_addr0=host_addr_i;r_addr1=0;
        a_din0=host_wdata_i;a_din1=0;b_din0=host_wdata_i;b_din1=0;
        r_din0=host_wdata_i;r_din1=0;
        if(state==IDLE&&host_we_i)case(host_bank_i)
            0:a_we0=1;1:b_we0=1;default:r_we0=1;
        endcase
        case(state)
            NTT_READ,INTT_READ:begin
                a_addr0=butterfly;a_addr1=butterfly+span;
            end
            NTT_WRITE:begin
                a_addr0=butterfly;a_addr1=butterfly+span;a_we0=1;a_we1=1;
                a_din0=butterfly_a_reg+fq_result_reg;
                a_din1=butterfly_a_reg-fq_result_reg;
            end
            INTT_SCALE_READ:a_addr0=butterfly;
            INTT_SCALE_WRITE:begin a_addr0=butterfly;a_we0=1;
                a_din0=fq_result_reg;end
            INTT_WRITE:begin
                a_addr0=butterfly;a_addr1=butterfly+span;a_we0=1;a_we1=1;
                a_din0=barrett_result_reg;
                a_din1=fq_result_reg;
            end
            BASEMUL_READ:begin
                a_addr0=2*pair_index;a_addr1=2*pair_index+1;
                b_addr0=2*pair_index;b_addr1=2*pair_index+1;
            end
            BASEMUL_WRITE:begin
                r_addr0=2*pair_index;r_addr1=2*pair_index+1;r_we0=1;r_we1=1;
                r_din0=basemul_p11z_reg+basemul_p00_reg;
                r_din1=basemul_p01_reg+basemul_p10_reg;
            end
            default:begin end
        endcase
        case(host_bank_i)
            0:host_rdata_o=a_dout0;1:host_rdata_o=b_dout0;
            default:host_rdata_o=r_dout0;
        endcase
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state<=IDLE; busy_o<=0; done_o<=0; layer<=0; span<=0;
            block_start<=0; butterfly<=0; zeta_index<=0; pair_index<=0;
            basemul_p11_reg<=0;basemul_p00_reg<=0;
            basemul_p01_reg<=0;basemul_p10_reg<=0;basemul_p11z_reg<=0;
            butterfly_a_reg<=0;intt_sum_reg<=0;intt_diff_reg<=0;
            fq_product_reg<=0;mont_multiplier_reg<=0;fq_result_reg<=0;
            barrett_accum_reg<=0;barrett_temp_reg<=0;barrett_result_reg<=0;
        end else begin
            done_o <= 0;
            case (state)
                IDLE: if (start_i) begin
                    busy_o<=1;
                    case (command_i)
                        CMD_NTT: begin layer<=1; span<=128; block_start<=0;
                            butterfly<=0; zeta_index<=1; state<=NTT_READ; end
                        CMD_INTT: begin butterfly<=0; state<=INTT_SCALE_READ; end
                        default: begin pair_index<=0; state<=BASEMUL_READ; end
                    endcase
                end

                NTT_READ:state<=NTT_MUL;
                NTT_MUL: begin
                    butterfly_a_reg<=a_dout0;
                    fq_product_reg<=a_dout1*zetas[zeta_index];
                    state<=NTT_MONT;
                end
                NTT_MONT: begin
                    mont_multiplier_reg<=fq_product_reg[15:0]*16'd62209;
                    state<=NTT_REDUCE;
                end
                NTT_REDUCE: begin
                    fq_result_reg<=(fq_product_reg-
                        mont_multiplier_reg*32'sd3329)>>>16;
                    state<=NTT_WRITE;
                end
                NTT_WRITE: begin
                    if (butterfly == block_start+span-1) begin
                        if (block_start+2*span >= 256) begin
                            if (layer == 7) begin state<=IDLE; busy_o<=0; done_o<=1; end
                            else begin layer<=layer+1; span<=span>>1; block_start<=0;
                                butterfly<=0; zeta_index<=zeta_index+1;state<=NTT_READ; end
                        end else begin
                            block_start<=block_start+2*span;
                            butterfly<=block_start+2*span;
                            zeta_index<=zeta_index+1;state<=NTT_READ;
                        end
                    end else begin butterfly<=butterfly+1;state<=NTT_READ;end
                end

                INTT_SCALE_READ:state<=INTT_SCALE_MUL;
                INTT_SCALE_MUL: begin
                    fq_product_reg<=a_dout0*16'sd1441;
                    state<=INTT_SCALE_MONT;
                end
                INTT_SCALE_MONT: begin
                    mont_multiplier_reg<=fq_product_reg[15:0]*16'd62209;
                    state<=INTT_SCALE_REDUCE;
                end
                INTT_SCALE_REDUCE: begin
                    fq_result_reg<=(fq_product_reg-
                        mont_multiplier_reg*32'sd3329)>>>16;
                    state<=INTT_SCALE_WRITE;
                end
                INTT_SCALE_WRITE: begin
                    if (butterfly==255) begin layer<=7; span<=2; block_start<=0;
                        butterfly<=0; zeta_index<=127; state<=INTT_READ; end
                    else begin butterfly<=butterfly+1;state<=INTT_SCALE_READ;end
                end

                INTT_READ:state<=INTT_PREP;
                INTT_PREP: begin
                    intt_sum_reg<=a_dout0+a_dout1;
                    intt_diff_reg<=a_dout1-a_dout0;
                    state<=INTT_MUL;
                end
                INTT_MUL: begin
                    fq_product_reg<=intt_diff_reg*zetas[zeta_index];
                    barrett_accum_reg<=32'sd20159*intt_sum_reg+32'sd33554432;
                    state<=INTT_MONT;
                end
                INTT_MONT: begin
                    mont_multiplier_reg<=fq_product_reg[15:0]*16'd62209;
                    barrett_temp_reg<=barrett_accum_reg>>>26;
                    state<=INTT_REDUCE;
                end
                INTT_REDUCE: begin
                    fq_result_reg<=(fq_product_reg-
                        mont_multiplier_reg*32'sd3329)>>>16;
                    barrett_result_reg<=intt_sum_reg-
                        barrett_temp_reg*32'sd3329;
                    state<=INTT_WRITE;
                end
                INTT_WRITE: begin
                    if (butterfly == block_start+span-1) begin
                        if (block_start+2*span >= 256) begin
                            if (layer==1) begin state<=IDLE; busy_o<=0; done_o<=1; end
                            else begin layer<=layer-1; span<=span<<1; block_start<=0;
                                butterfly<=0; zeta_index<=(1<<(layer-1))-1;state<=INTT_READ; end
                        end else begin block_start<=block_start+2*span;
                            butterfly<=block_start+2*span; zeta_index<=zeta_index-1;state<=INTT_READ; end
                    end else begin butterfly<=butterfly+1;state<=INTT_READ;end
                end

                BASEMUL_READ:state<=BASEMUL_MUL;
                BASEMUL_MUL:begin
                    basemul_p11_reg<=fqmul(a_dout1,b_dout1);
                    basemul_p00_reg<=fqmul(a_dout0,b_dout0);
                    basemul_p01_reg<=fqmul(a_dout0,b_dout1);
                    basemul_p10_reg<=fqmul(a_dout1,b_dout0);
                    state<=BASEMUL_ZETA;
                end
                BASEMUL_ZETA:begin
                    basemul_p11z_reg<=fqmul(basemul_p11_reg,pair_index[0]
                        ? -zetas[64+(pair_index>>1)]:zetas[64+(pair_index>>1)]);
                    state<=BASEMUL_WRITE;
                end
                BASEMUL_WRITE: begin
                    if (pair_index==127) begin state<=IDLE; busy_o<=0; done_o<=1; end
                    else begin pair_index<=pair_index+1;state<=BASEMUL_READ;end
                end
                default: state<=IDLE;
            endcase
        end
    end
endmodule
