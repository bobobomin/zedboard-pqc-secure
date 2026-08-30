`timescale 1ns/1ps

module keccak_f1600 (
    input  logic          clk_i,
    input  logic          rst_ni,
    input  logic          start_i,
    input  logic [1599:0] state_i,
    output logic          busy_o,
    output logic          done_o,
    output logic [1599:0] state_o
);
    logic [1599:0] state_reg;
    logic [1599:0] next_state;
    logic [4:0] round_index;
    logic [63:0] a[0:24], c[0:4], d[0:4], b[0:24], n[0:24];
    integer x, y, idx, destination_y;

    function automatic logic [63:0] rotl64(input logic [63:0] v,
                                            input integer amount);
        if (amount == 0) rotl64 = v;
        else rotl64 = (v << amount) | (v >> (64-amount));
    endfunction

    function automatic integer rho_offset(input integer lane_index);
        case (lane_index)
             0: rho_offset=0;   1: rho_offset=1;   2: rho_offset=62;
             3: rho_offset=28;  4: rho_offset=27;  5: rho_offset=36;
             6: rho_offset=44;  7: rho_offset=6;   8: rho_offset=55;
             9: rho_offset=20; 10: rho_offset=3;  11: rho_offset=10;
            12: rho_offset=43; 13: rho_offset=25; 14: rho_offset=39;
            15: rho_offset=41; 16: rho_offset=45; 17: rho_offset=15;
            18: rho_offset=21; 19: rho_offset=8;  20: rho_offset=18;
            21: rho_offset=2;  22: rho_offset=61; 23: rho_offset=56;
            default: rho_offset=14;
        endcase
    endfunction

    function automatic logic [63:0] round_constant(input logic [4:0] r);
        case (r)
             0: round_constant=64'h0000000000000001;
             1: round_constant=64'h0000000000008082;
             2: round_constant=64'h800000000000808a;
             3: round_constant=64'h8000000080008000;
             4: round_constant=64'h000000000000808b;
             5: round_constant=64'h0000000080000001;
             6: round_constant=64'h8000000080008081;
             7: round_constant=64'h8000000000008009;
             8: round_constant=64'h000000000000008a;
             9: round_constant=64'h0000000000000088;
            10: round_constant=64'h0000000080008009;
            11: round_constant=64'h000000008000000a;
            12: round_constant=64'h000000008000808b;
            13: round_constant=64'h800000000000008b;
            14: round_constant=64'h8000000000008089;
            15: round_constant=64'h8000000000008003;
            16: round_constant=64'h8000000000008002;
            17: round_constant=64'h8000000000000080;
            18: round_constant=64'h000000000000800a;
            19: round_constant=64'h800000008000000a;
            20: round_constant=64'h8000000080008081;
            21: round_constant=64'h8000000000008080;
            22: round_constant=64'h0000000080000001;
            default: round_constant=64'h8000000080008008;
        endcase
    endfunction

    always_comb begin
        for (idx=0; idx<25; idx=idx+1) begin
            a[idx] = state_reg[64*idx +: 64];
            b[idx] = 64'd0;
            n[idx] = 64'd0;
        end

        /* Theta. */
        for (x=0; x<5; x=x+1)
            c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
        for (x=0; x<5; x=x+1)
            d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5],1);
        for (y=0; y<5; y=y+1)
            for (x=0; x<5; x=x+1)
                n[x+5*y] = a[x+5*y] ^ d[x];

        /* Rho and Pi: B[y,2*x+3*y] = ROT(A[x,y],r[x,y]). */
        for (y=0; y<5; y=y+1) begin
            for (x=0; x<5; x=x+1) begin
                destination_y = (2*x + 3*y) % 5;
                b[y + 5*destination_y] =
                    rotl64(n[x+5*y],rho_offset(x+5*y));
            end
        end

        /* Chi. */
        for (y=0; y<5; y=y+1)
            for (x=0; x<5; x=x+1)
                n[x+5*y] = b[x+5*y]
                           ^ ((~b[((x+1)%5)+5*y])
                              & b[((x+2)%5)+5*y]);

        /* Iota. */
        n[0] = n[0] ^ round_constant(round_index);
        for (idx=0; idx<25; idx=idx+1)
            next_state[64*idx +: 64] = n[idx];
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state_reg  <= '0;
            state_o    <= '0;
            round_index<= '0;
            busy_o     <= 1'b0;
            done_o     <= 1'b0;
        end else begin
            done_o <= 1'b0;
            if (start_i && !busy_o) begin
                state_reg   <= state_i;
                round_index <= 5'd0;
                busy_o      <= 1'b1;
            end else if (busy_o) begin
                if (round_index == 5'd23) begin
                    state_o <= next_state;
                    busy_o  <= 1'b0;
                    done_o  <= 1'b1;
                end else begin
                    state_reg   <= next_state;
                    round_index <= round_index + 5'd1;
                end
            end
        end
    end
endmodule
