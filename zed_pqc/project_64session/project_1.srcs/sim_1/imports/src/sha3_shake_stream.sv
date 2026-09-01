`timescale 1ns/1ps

module sha3_shake_stream (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        start_i,
    input  logic [1:0]  mode_i,
    input  logic [15:0] output_length_i,
    input  logic [7:0]  input_byte_i,
    input  logic        input_valid_i,
    output logic        input_ready_o,
    input  logic        finalize_i,
    output logic [7:0]  output_byte_o,
    output logic        output_valid_o,
    input  logic        output_ready_i,
    output logic        busy_o,
    output logic        done_o
);
    localparam logic [1:0] MODE_SHA3_256 = 2'd0;
    localparam logic [1:0] MODE_SHA3_512 = 2'd1;
    localparam logic [1:0] MODE_SHAKE128 = 2'd2;
    localparam logic [1:0] MODE_SHAKE256 = 2'd3;

    typedef enum logic [2:0] {
        S_IDLE, S_ABSORB, S_PAD_FINAL, S_PERM_ABSORB, S_PERM_FINAL,
        S_SQUEEZE, S_PERM_SQUEEZE
    } sponge_state_t;

    /* This state selects the data input and the enable of all 1600 sponge
       flops.  As a single net it reaches every one of them and spends most of
       its path in routing, so it is replicated. */
    (* max_fanout = 64 *) sponge_state_t control_state;
    logic [1599:0] sponge_state;
    logic [1599:0] sponge_xored;
    logic [1599:0] permutation_output;
    logic permutation_start, permutation_done;
    logic [7:0] selected_rate_bytes, selected_suffix;
    logic [7:0] rate_bytes, rate_last, suffix;
    logic [7:0] absorb_position, squeeze_position;
    logic [7:0] xor_position, xor_byte;
    logic [15:0] output_length, output_count;

    always_comb begin
        case (mode_i)
            MODE_SHA3_256: begin selected_rate_bytes=8'd136; selected_suffix=8'h06; end
            MODE_SHA3_512: begin selected_rate_bytes=8'd72;  selected_suffix=8'h06; end
            MODE_SHAKE128: begin selected_rate_bytes=8'd168; selected_suffix=8'h1f; end
            default:       begin selected_rate_bytes=8'd136; selected_suffix=8'h1f; end
        endcase
    end

    /*
     * A single byte-wide XOR into the sponge.  Absorbing a message byte, the
     * domain suffix and the 0x80 pad all take this one path, so the 1600-bit
     * update network exists once instead of once per case.
     */
    always_comb begin
        if (control_state == S_PAD_FINAL) begin
            xor_position = rate_last;
            xor_byte     = 8'h80;
        end else begin
            xor_position = absorb_position;
            xor_byte     = input_valid_i ? input_byte_i : suffix;
        end
        sponge_xored = sponge_state;
        sponge_xored[8*xor_position +: 8] =
            sponge_state[8*xor_position +: 8] ^ xor_byte;
    end

    (* max_fanout = 64 *) logic absorb_active;
    assign absorb_active  = (control_state == S_ABSORB);
    assign input_ready_o  = absorb_active;
    assign output_valid_o = (control_state == S_SQUEEZE);
    assign output_byte_o  = sponge_state[8*squeeze_position +: 8];
    assign busy_o         = (control_state != S_IDLE);

    keccak_f1600 u_permutation (
        .clk_i(clk_i), .rst_ni(rst_ni), .start_i(permutation_start),
        .state_i(sponge_state), .busy_o(),
        .done_o(permutation_done), .state_o(permutation_output)
    );

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            control_state    <= S_IDLE;
            sponge_state     <= '0;
            permutation_start<= 1'b0;
            absorb_position  <= '0;
            squeeze_position <= '0;
            output_length    <= '0;
            output_count     <= '0;
            rate_bytes       <= 8'd136;
            rate_last        <= 8'd135;
            suffix           <= 8'h06;
            done_o           <= 1'b0;
        end else begin
            permutation_start <= 1'b0;
            done_o <= 1'b0;
            case (control_state)
                S_IDLE: if (start_i) begin
                    sponge_state     <= '0;
                    absorb_position  <= '0;
                    squeeze_position <= '0;
                    output_count     <= '0;
                    output_length    <= output_length_i;
                    rate_bytes       <= selected_rate_bytes;
                    rate_last        <= selected_rate_bytes - 8'd1;
                    suffix           <= selected_suffix;
                    control_state    <= S_ABSORB;
                end

                S_ABSORB: begin
                    if (input_valid_i && absorb_active) begin
                        sponge_state <= sponge_xored;
                        if (absorb_position == rate_last) begin
                            permutation_start <= 1'b1;
                            absorb_position   <= 8'd0;
                            control_state     <= S_PERM_ABSORB;
                        end else begin
                            absorb_position <= absorb_position + 8'd1;
                        end
                    end else if (finalize_i) begin
                        sponge_state  <= sponge_xored;   /* domain suffix */
                        control_state <= S_PAD_FINAL;
                    end
                end

                /* Second pad byte goes through the same XOR path one clock later. */
                S_PAD_FINAL: begin
                    sponge_state      <= sponge_xored;   /* 0x80 at rate_last */
                    permutation_start <= 1'b1;
                    control_state     <= S_PERM_FINAL;
                end

                S_PERM_ABSORB: if (permutation_done) begin
                    sponge_state <= permutation_output;
                    control_state <= S_ABSORB;
                end

                S_PERM_FINAL: if (permutation_done) begin
                    sponge_state     <= permutation_output;
                    squeeze_position <= 8'd0;
                    output_count     <= 16'd0;
                    if (output_length == 16'd0) begin
                        done_o        <= 1'b1;
                        control_state <= S_IDLE;
                    end else begin
                        control_state <= S_SQUEEZE;
                    end
                end

                S_SQUEEZE: if (output_valid_o && output_ready_i) begin
                    if (output_count + 16'd1 == output_length) begin
                        done_o        <= 1'b1;
                        control_state <= S_IDLE;
                    end else if (squeeze_position == rate_last) begin
                        permutation_start <= 1'b1;
                        squeeze_position  <= 8'd0;
                        output_count      <= output_count + 16'd1;
                        control_state     <= S_PERM_SQUEEZE;
                    end else begin
                        squeeze_position <= squeeze_position + 8'd1;
                        output_count     <= output_count + 16'd1;
                    end
                end

                S_PERM_SQUEEZE: if (permutation_done) begin
                    sponge_state <= permutation_output;
                    control_state <= S_SQUEEZE;
                end

                default: control_state <= S_IDLE;
            endcase
        end
    end
endmodule
