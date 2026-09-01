`timescale 1ns/1ps

module chacha20_block (
    input  logic         clk_i,
    input  logic         rst_ni,
    input  logic         start_i,
    input  logic [255:0] key_i,
    input  logic [95:0]  nonce_i,
    input  logic [31:0]  block_counter_i,
    output logic         busy_o,
    output logic         done_o,
    output logic [511:0] block_o
);

    logic [31:0] initial_state [0:15];
    logic [31:0] working_state [0:15];
    logic [31:0] round_state   [0:15];
    logic [5:0]  step_index;
    integer i_comb;
    integer i_seq;

    function automatic logic [31:0] rotl32(
        input logic [31:0] value,
        input integer amount
    );
        rotl32 = (value << amount) | (value >> (32 - amount));
    endfunction

    /*
     * Half a quarter round: two of the four dependent additions.  The four
     * additions of a full quarter round chain through one another, so running
     * all of them in one clock stacks sixteen 32-bit carry chains per round.
     * Each step below evaluates one half, selected by second_i.
     */
    task automatic quarter_round_half(
        input  logic       second_i,
        inout logic [31:0] a,
        inout logic [31:0] b,
        inout logic [31:0] c,
        inout logic [31:0] d
    );
        begin
            if (!second_i) begin
                a = a + b; d = rotl32(d ^ a, 16);
                c = c + d; b = rotl32(b ^ c, 12);
            end else begin
                a = a + b; d = rotl32(d ^ a,  8);
                c = c + d; b = rotl32(b ^ c,  7);
            end
        end
    endtask

    /*
     * Byte packing convention used by every module in this package:
     * byte 0 is stored in bits [7:0], byte 1 in [15:8], and so on.
     * Consequently, each 32-bit slice below is already the RFC 8439
     * little-endian word value.
     */
    always_comb begin
        for (i_comb = 0; i_comb < 16; i_comb = i_comb + 1)
            round_state[i_comb] = working_state[i_comb];

        /* step_index[1] picks column vs diagonal, step_index[0] picks the half. */
        if (step_index[1] == 1'b0) begin
            quarter_round_half(step_index[0], round_state[0], round_state[4],
                               round_state[8], round_state[12]);
            quarter_round_half(step_index[0], round_state[1], round_state[5],
                               round_state[9], round_state[13]);
            quarter_round_half(step_index[0], round_state[2], round_state[6],
                               round_state[10], round_state[14]);
            quarter_round_half(step_index[0], round_state[3], round_state[7],
                               round_state[11], round_state[15]);
        end else begin
            quarter_round_half(step_index[0], round_state[0], round_state[5],
                               round_state[10], round_state[15]);
            quarter_round_half(step_index[0], round_state[1], round_state[6],
                               round_state[11], round_state[12]);
            quarter_round_half(step_index[0], round_state[2], round_state[7],
                               round_state[8], round_state[13]);
            quarter_round_half(step_index[0], round_state[3], round_state[4],
                               round_state[9], round_state[14]);
        end
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            busy_o      <= 1'b0;
            done_o      <= 1'b0;
            block_o     <= '0;
            step_index  <= '0;
            for (i_seq = 0; i_seq < 16; i_seq = i_seq + 1) begin
                initial_state[i_seq] <= '0;
                working_state[i_seq] <= '0;
            end
        end else begin
            done_o <= 1'b0;

            if (start_i && !busy_o) begin
                initial_state[0] <= 32'h61707865;
                initial_state[1] <= 32'h3320646e;
                initial_state[2] <= 32'h79622d32;
                initial_state[3] <= 32'h6b206574;
                working_state[0] <= 32'h61707865;
                working_state[1] <= 32'h3320646e;
                working_state[2] <= 32'h79622d32;
                working_state[3] <= 32'h6b206574;

                for (i_seq = 0; i_seq < 8; i_seq = i_seq + 1) begin
                    initial_state[4+i_seq] <= key_i[32*i_seq +: 32];
                    working_state[4+i_seq] <= key_i[32*i_seq +: 32];
                end

                initial_state[12] <= block_counter_i;
                working_state[12] <= block_counter_i;
                for (i_seq = 0; i_seq < 3; i_seq = i_seq + 1) begin
                    initial_state[13+i_seq] <= nonce_i[32*i_seq +: 32];
                    working_state[13+i_seq] <= nonce_i[32*i_seq +: 32];
                end

                step_index  <= 6'd0;
                busy_o      <= 1'b1;
            end else if (busy_o) begin
                /* 10 double rounds = 20 half rounds = 40 steps, then the feed-forward add. */
                if (step_index == 6'd40) begin
                    for (i_seq = 0; i_seq < 16; i_seq = i_seq + 1)
                        block_o[32*i_seq +: 32] <= working_state[i_seq] + initial_state[i_seq];
                    busy_o <= 1'b0;
                    done_o <= 1'b1;
                end else begin
                    for (i_seq = 0; i_seq < 16; i_seq = i_seq + 1)
                        working_state[i_seq] <= round_state[i_seq];
                    step_index <= step_index + 6'd1;
                end
            end
        end
    end

endmodule
