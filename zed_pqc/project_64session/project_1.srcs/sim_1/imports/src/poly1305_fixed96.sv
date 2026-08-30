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

    typedef enum logic [2:0] {
        S_IDLE,
        S_LOAD_BLOCK,
        S_MULTIPLY,
        S_NORMALIZE,
        S_FINAL
    } state_t;

    state_t state;
    logic [767:0] message_reg;
    logic [127:0] s_reg;
    logic [127:0] clamped_r_input;
    logic [25:0]  r_limb [0:4];
    logic [26:0]  h_limb [0:4];
    logic [27:0]  a_limb [0:4];
    logic [63:0]  d_acc  [0:4];
    logic [2:0]   block_index;
    logic [2:0]   output_index;
    logic [2:0]   term_index;

    logic [127:0] current_block;
    logic [25:0]  message_limb [0:4];
    logic [27:0]  multiply_a;
    logic [28:0]  multiply_b;
    logic [56:0]  multiply_result;
    integer       selected_r;
    integer       reset_index;

    logic [63:0] n0, n1, n2, n3, n4;
    logic [63:0] c0, c1, c2, c3, c4, c5;
    logic [26:0] normalized_h [0:4];

    logic [130:0] h_value;
    logic [130:0] canonical_h;

    always_comb clamped_r_input = one_time_key_i[127:0] & R_CLAMP_MASK;

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
     * multiplied by five because 2^130 == 5 mod (2^130-5).
     */
    always_comb begin
        multiply_a = a_limb[term_index];
        if (term_index <= output_index) begin
            selected_r = output_index - term_index;
            multiply_b = {3'b000, r_limb[selected_r]};
        end else begin
            selected_r = output_index + 5 - term_index;
            multiply_b = r_limb[selected_r] * 3'd5;
        end
        multiply_result = multiply_a * multiply_b;
    end

    /* Carry propagation for five radix-2^26 limbs. */
    always_comb begin
        n0 = d_acc[0];
        n1 = d_acc[1];
        n2 = d_acc[2];
        n3 = d_acc[3];
        n4 = d_acc[4];

        c0 = n0 >> 26; n0 = n0 & LIMB_MASK; n1 = n1 + c0;
        c1 = n1 >> 26; n1 = n1 & LIMB_MASK; n2 = n2 + c1;
        c2 = n2 >> 26; n2 = n2 & LIMB_MASK; n3 = n3 + c2;
        c3 = n3 >> 26; n3 = n3 & LIMB_MASK; n4 = n4 + c3;
        c4 = n4 >> 26; n4 = n4 & LIMB_MASK; n0 = n0 + c4 * 3'd5;
        c5 = n0 >> 26; n0 = n0 & LIMB_MASK; n1 = n1 + c5;

        normalized_h[0] = n0[26:0];
        normalized_h[1] = n1[26:0];
        normalized_h[2] = n2[26:0];
        normalized_h[3] = n3[26:0];
        normalized_h[4] = n4[26:0];
    end

    /* Canonical final reduction before adding s modulo 2^128. */
    always_comb begin
        h_value = 131'd0;
        h_value = h_value + ({{104{1'b0}}, h_limb[0]}      );
        h_value = h_value + ({{104{1'b0}}, h_limb[1]} << 26);
        h_value = h_value + ({{104{1'b0}}, h_limb[2]} << 52);
        h_value = h_value + ({{104{1'b0}}, h_limb[3]} << 78);
        h_value = h_value + ({{104{1'b0}}, h_limb[4]} << 104);
        if (h_value >= P130)
            canonical_h = h_value - P130;
        else
            canonical_h = h_value;
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state         <= S_IDLE;
            message_reg   <= '0;
            s_reg         <= '0;
            block_index   <= '0;
            output_index  <= '0;
            term_index    <= '0;
            busy_o        <= 1'b0;
            done_o        <= 1'b0;
            tag_o         <= '0;
            for (reset_index = 0; reset_index < 5; reset_index = reset_index + 1) begin
                r_limb[reset_index] <= '0;
                h_limb[reset_index] <= '0;
                a_limb[reset_index] <= '0;
                d_acc[reset_index]  <= '0;
            end
        end else begin
            done_o <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start_i) begin
                        r_limb[0] <= clamped_r_input[25:0];
                        r_limb[1] <= clamped_r_input[51:26];
                        r_limb[2] <= clamped_r_input[77:52];
                        r_limb[3] <= clamped_r_input[103:78];
                        r_limb[4] <= clamped_r_input[127:104];
                        s_reg       <= one_time_key_i[255:128];
                        message_reg <= message_i;
                        block_index <= 3'd0;
                        busy_o      <= 1'b1;
                        for (reset_index = 0; reset_index < 5; reset_index = reset_index + 1)
                            h_limb[reset_index] <= '0;
                        state <= S_LOAD_BLOCK;
                    end
                end

                S_LOAD_BLOCK: begin
                    for (reset_index = 0; reset_index < 5; reset_index = reset_index + 1) begin
                        a_limb[reset_index] <= h_limb[reset_index] + message_limb[reset_index];
                        d_acc[reset_index]  <= '0;
                    end
                    output_index <= 3'd0;
                    term_index   <= 3'd0;
                    state        <= S_MULTIPLY;
                end

                S_MULTIPLY: begin
                    d_acc[output_index] <= d_acc[output_index] + multiply_result;
                    if (term_index == 3'd4) begin
                        term_index <= 3'd0;
                        if (output_index == 3'd4) begin
                            state <= S_NORMALIZE;
                        end else begin
                            output_index <= output_index + 3'd1;
                        end
                    end else begin
                        term_index <= term_index + 3'd1;
                    end
                end

                S_NORMALIZE: begin
                    for (reset_index = 0; reset_index < 5; reset_index = reset_index + 1)
                        h_limb[reset_index] <= normalized_h[reset_index];
                    if (block_index == 3'd5) begin
                        state <= S_FINAL;
                    end else begin
                        block_index <= block_index + 3'd1;
                        state       <= S_LOAD_BLOCK;
                    end
                end

                S_FINAL: begin
                    tag_o  <= canonical_h[127:0] + s_reg;
                    busy_o <= 1'b0;
                    done_o <= 1'b1;
                    state  <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
