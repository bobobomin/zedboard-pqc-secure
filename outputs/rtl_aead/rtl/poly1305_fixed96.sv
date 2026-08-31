`timescale 1ns/1ps

module poly1305_fixed96 (
    input  logic         clk_i,
    input  logic         rst_ni,
    input  logic         start_i,
    input  logic [255:0] one_time_key_i,
    input  logic [767:0] message_i,
    output logic         busy_o,
    output logic         done_o,
    output logic [127:0] tag_o
);

    localparam logic [127:0] R_CLAMP_MASK =
        128'h0ffffffc0ffffffc0ffffffc0fffffff;
    localparam logic [130:0] P130 = (131'd1 << 130) - 131'd5;
    localparam logic [63:0]  LIMB_MASK = 64'h0000000003ffffff;

    typedef enum logic [3:0] {
        S_IDLE,
        S_LOAD_BLOCK,
        S_SELECT,
        S_MULTIPLY,
        S_ACCUMULATE,
        S_NORM0,
        S_NORM1,
        S_NORM2,
        S_NORM3,
        S_NORM4,
        S_NORM5,
        S_PACK,
        S_REDUCE,
        S_FINAL
    } state_t;

    state_t state;
    logic [767:0] message_reg;
    logic [127:0] s_reg;
    logic [127:0] clamped_r_input;
    logic [25:0]  key_limb [0:4];
    logic [25:0]  r_limb   [0:4];
    logic [28:0]  r5_limb  [0:4];
    logic [26:0]  h_limb   [0:4];
    logic [27:0]  a_limb   [0:4];
    logic [63:0]  d_acc    [0:4];
    logic [63:0]  acc_reg;
    logic [27:0]  mul_a_reg;
    logic [28:0]  mul_b_reg;
    logic [56:0]  product_reg;
    logic [130:0] h_value_reg;
    logic [130:0] canonical_reg;
    logic [2:0]   block_index;
    logic [2:0]   output_index;
    logic [2:0]   term_index;

    logic [127:0] current_block;
    logic [25:0]  message_limb [0:4];
    logic [27:0]  multiply_a;
    logic [28:0]  multiply_b;
    integer       selected_r;
    integer       reset_index;

    logic [26:0] packed_limb2, packed_limb3, packed_limb4;

    always_comb clamped_r_input = one_time_key_i[127:0] & R_CLAMP_MASK;

    always_comb begin
        key_limb[0] = clamped_r_input[25:0];
        key_limb[1] = clamped_r_input[51:26];
        key_limb[2] = clamped_r_input[77:52];
        key_limb[3] = clamped_r_input[103:78];
        key_limb[4] = clamped_r_input[127:104];
    end

    always_comb begin
        current_block  = message_reg[128*block_index +: 128];
        message_limb[0] = current_block[25:0];
        message_limb[1] = current_block[51:26];
        message_limb[2] = current_block[77:52];
        message_limb[3] = current_block[103:78];
        /* Full 16-byte block: append the mandatory 1 bit at bit 128. */
        message_limb[4] = {1'b1, current_block[127:104]};
    end

    /*
     * One shared 28x29-bit multiplier evaluates the 25 schoolbook terms.
     * For output limb j and input limb i, terms that wrap modulo five are
     * multiplied by five because 2^130 == 5 mod (2^130-5).  r is fixed for the
     * whole message, so the five multiples are computed once in S_IDLE and the
     * multiplier below is the only one on the datapath.
     */
    always_comb begin
        multiply_a = a_limb[term_index];
        if (term_index <= output_index) begin
            selected_r = output_index - term_index;
            multiply_b = {3'b000, r_limb[selected_r]};
        end else begin
            selected_r = output_index + 5 - term_index;
            multiply_b = r5_limb[selected_r];
        end
    end

    /*
     * S_NORM0..S_NORM5 leave h_limb[0] and h_limb[2..4] below 2^26; only
     * h_limb[1] can reach 2^26 because it absorbs the last carry.  Packing the
     * limbs into the 131-bit value therefore needs one carry ripple across the
     * upper three limbs instead of four wide additions.
     */
    always_comb begin
        packed_limb2 = h_limb[2] + {26'd0, h_limb[1][26]};
        packed_limb3 = h_limb[3] + {26'd0, packed_limb2[26]};
        packed_limb4 = h_limb[4] + {26'd0, packed_limb3[26]};
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state         <= S_IDLE;
            message_reg   <= '0;
            s_reg         <= '0;
            block_index   <= '0;
            output_index  <= '0;
            term_index    <= '0;
            acc_reg       <= '0;
            mul_a_reg     <= '0;
            mul_b_reg     <= '0;
            product_reg   <= '0;
            h_value_reg   <= '0;
            canonical_reg <= '0;
            busy_o        <= 1'b0;
            done_o        <= 1'b0;
            tag_o         <= '0;
            for (reset_index = 0; reset_index < 5; reset_index = reset_index + 1) begin
                r_limb[reset_index]  <= '0;
                r5_limb[reset_index] <= '0;
                h_limb[reset_index]  <= '0;
                a_limb[reset_index]  <= '0;
                d_acc[reset_index]   <= '0;
            end
        end else begin
            done_o <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start_i) begin
                        for (reset_index = 0; reset_index < 5; reset_index = reset_index + 1) begin
                            r_limb[reset_index]  <= key_limb[reset_index];
                            r5_limb[reset_index] <= key_limb[reset_index] * 3'd5;
                            h_limb[reset_index]  <= '0;
                        end
                        s_reg       <= one_time_key_i[255:128];
                        message_reg <= message_i;
                        block_index <= 3'd0;
                        busy_o      <= 1'b1;
                        state <= S_LOAD_BLOCK;
                    end
                end

                S_LOAD_BLOCK: begin
                    for (reset_index = 0; reset_index < 5; reset_index = reset_index + 1)
                        a_limb[reset_index] <= h_limb[reset_index] + message_limb[reset_index];
                    acc_reg      <= 64'd0;
                    output_index <= 3'd0;
                    term_index   <= 3'd0;
                    state        <= S_SELECT;
                end

                /*
                 * Operand selection, multiply and accumulate each get their own
                 * clock.  multiply_a x multiply_b is 28x29 and spans two DSPs,
                 * so the term/limb multiplexers in front of it have to come out
                 * of the same clock as the multiply itself.
                 */
                S_SELECT: begin
                    mul_a_reg <= multiply_a;
                    mul_b_reg <= multiply_b;
                    state     <= S_MULTIPLY;
                end

                S_MULTIPLY: begin
                    product_reg <= mul_a_reg * mul_b_reg;
                    state       <= S_ACCUMULATE;
                end

                S_ACCUMULATE: begin
                    if (term_index == 3'd4) begin
                        d_acc[output_index] <= acc_reg + {7'd0, product_reg};
                        acc_reg    <= 64'd0;
                        term_index <= 3'd0;
                        if (output_index == 3'd4) begin
                            state <= S_NORM0;
                        end else begin
                            output_index <= output_index + 3'd1;
                            state        <= S_SELECT;
                        end
                    end else begin
                        acc_reg    <= acc_reg + {7'd0, product_reg};
                        term_index <= term_index + 3'd1;
                        state      <= S_SELECT;
                    end
                end

                /* One carry step per clock across the five radix-2^26 limbs. */
                S_NORM0: begin
                    d_acc[0] <= d_acc[0] & LIMB_MASK;
                    d_acc[1] <= d_acc[1] + (d_acc[0] >> 26);
                    state    <= S_NORM1;
                end

                S_NORM1: begin
                    d_acc[1] <= d_acc[1] & LIMB_MASK;
                    d_acc[2] <= d_acc[2] + (d_acc[1] >> 26);
                    state    <= S_NORM2;
                end

                S_NORM2: begin
                    d_acc[2] <= d_acc[2] & LIMB_MASK;
                    d_acc[3] <= d_acc[3] + (d_acc[2] >> 26);
                    state    <= S_NORM3;
                end

                S_NORM3: begin
                    d_acc[3] <= d_acc[3] & LIMB_MASK;
                    d_acc[4] <= d_acc[4] + (d_acc[3] >> 26);
                    state    <= S_NORM4;
                end

                S_NORM4: begin
                    d_acc[4] <= d_acc[4] & LIMB_MASK;
                    d_acc[0] <= d_acc[0] + ((d_acc[4] >> 26) * 3'd5);
                    state    <= S_NORM5;
                end

                S_NORM5: begin
                    h_limb[0] <= d_acc[0][25:0];
                    h_limb[1] <= d_acc[1] + (d_acc[0] >> 26);
                    h_limb[2] <= d_acc[2][26:0];
                    h_limb[3] <= d_acc[3][26:0];
                    h_limb[4] <= d_acc[4][26:0];
                    if (block_index == 3'd5) begin
                        state <= S_PACK;
                    end else begin
                        block_index <= block_index + 3'd1;
                        state       <= S_LOAD_BLOCK;
                    end
                end

                S_PACK: begin
                    h_value_reg <= {packed_limb4,
                                    packed_limb3[25:0],
                                    packed_limb2[25:0],
                                    h_limb[1][25:0],
                                    h_limb[0][25:0]};
                    state       <= S_REDUCE;
                end

                /* Canonical final reduction before adding s modulo 2^128. */
                S_REDUCE: begin
                    if (h_value_reg >= P130)
                        canonical_reg <= h_value_reg - P130;
                    else
                        canonical_reg <= h_value_reg;
                    state <= S_FINAL;
                end

                S_FINAL: begin
                    tag_o  <= canonical_reg[127:0] + s_reg;
                    busy_o <= 1'b0;
                    done_o <= 1'b1;
                    state  <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
