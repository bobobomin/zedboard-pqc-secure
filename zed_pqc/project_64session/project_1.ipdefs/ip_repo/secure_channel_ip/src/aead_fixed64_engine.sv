`timescale 1ns/1ps

/*
 * Shared encrypt/decrypt engine for one fixed 64-byte packet.
 * Decryption authenticates before releasing plaintext.
 */
module aead_fixed64_engine (
    input  logic         clk_i,
    input  logic         rst_ni,
    input  logic         start_i,
    input  logic         decrypt_i,
    input  logic [255:0] key_i,
    input  logic [95:0]  nonce_i,
    input  logic [127:0] aad_i,
    input  logic [511:0] data_i,
    input  logic [127:0] received_tag_i,
    output logic         busy_o,
    output logic         done_o,
    output logic         auth_ok_o,
    output logic [511:0] data_o,
    output logic [127:0] tag_o
);

    typedef enum logic [2:0] {
        S_IDLE,
        S_WAIT_POLY_KEY,
        S_WAIT_ENCRYPT_STREAM,
        S_WAIT_ENCRYPT_TAG,
        S_WAIT_DECRYPT_TAG,
        S_WAIT_DECRYPT_STREAM
    } state_t;

    state_t state;
    logic         decrypt_reg;
    logic [255:0] key_reg;
    logic [95:0]  nonce_reg;
    logic [127:0] aad_reg;
    logic [511:0] data_reg;
    logic [127:0] received_tag_reg;
    logic [255:0] poly_key_reg;
    logic [767:0] poly_message_reg;

    logic         chacha_start;
    logic [31:0]  chacha_counter;
    logic         chacha_done;
    logic [511:0] chacha_block;
    logic         poly_start;
    logic         poly_done;
    logic [127:0] poly_tag;
    logic         tag_matches;

    assign tag_matches = ~(|(poly_tag ^ received_tag_reg));

    chacha20_block u_chacha20 (
        .clk_i(clk_i), .rst_ni(rst_ni), .start_i(chacha_start),
        .key_i(key_reg), .nonce_i(nonce_reg),
        .block_counter_i(chacha_counter), .busy_o(),
        .done_o(chacha_done), .block_o(chacha_block)
    );

    poly1305_fixed96 u_poly1305 (
        .clk_i(clk_i), .rst_ni(rst_ni), .start_i(poly_start),
        .one_time_key_i(poly_key_reg), .message_i(poly_message_reg),
        .busy_o(), .done_o(poly_done), .tag_o(poly_tag)
    );

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state             <= S_IDLE;
            decrypt_reg       <= 1'b0;
            key_reg           <= '0;
            nonce_reg         <= '0;
            aad_reg           <= '0;
            data_reg          <= '0;
            received_tag_reg  <= '0;
            poly_key_reg      <= '0;
            poly_message_reg  <= '0;
            chacha_start      <= 1'b0;
            chacha_counter    <= '0;
            poly_start        <= 1'b0;
            busy_o            <= 1'b0;
            done_o            <= 1'b0;
            auth_ok_o         <= 1'b0;
            data_o            <= '0;
            tag_o             <= '0;
        end else begin
            chacha_start <= 1'b0;
            poly_start   <= 1'b0;
            done_o       <= 1'b0;

            case (state)
                S_IDLE: begin
                    if (start_i) begin
                        decrypt_reg      <= decrypt_i;
                        key_reg          <= key_i;
                        nonce_reg        <= nonce_i;
                        aad_reg          <= aad_i;
                        data_reg         <= data_i;
                        received_tag_reg <= received_tag_i;
                        data_o           <= '0;
                        tag_o            <= '0;
                        auth_ok_o        <= 1'b0;
                        chacha_counter   <= 32'd0;
                        chacha_start     <= 1'b1;
                        busy_o           <= 1'b1;
                        state            <= S_WAIT_POLY_KEY;
                    end
                end

                S_WAIT_POLY_KEY: begin
                    if (chacha_done) begin
                        poly_key_reg <= chacha_block[255:0];
                        if (decrypt_reg) begin
                            poly_message_reg[127:0]   <= aad_reg;
                            poly_message_reg[639:128] <= data_reg;
                            poly_message_reg[767:640] <= {64'd64, 64'd16};
                            poly_start <= 1'b1;
                            state      <= S_WAIT_DECRYPT_TAG;
                        end else begin
                            chacha_counter <= 32'd1;
                            chacha_start   <= 1'b1;
                            state          <= S_WAIT_ENCRYPT_STREAM;
                        end
                    end
                end

                S_WAIT_ENCRYPT_STREAM: begin
                    if (chacha_done) begin
                        data_o <= data_reg ^ chacha_block;
                        poly_message_reg[127:0]   <= aad_reg;
                        poly_message_reg[639:128] <= data_reg ^ chacha_block;
                        poly_message_reg[767:640] <= {64'd64, 64'd16};
                        poly_start <= 1'b1;
                        state      <= S_WAIT_ENCRYPT_TAG;
                    end
                end

                S_WAIT_ENCRYPT_TAG: begin
                    if (poly_done) begin
                        tag_o     <= poly_tag;
                        auth_ok_o <= 1'b1;
                        busy_o    <= 1'b0;
                        done_o    <= 1'b1;
                        state     <= S_IDLE;
                    end
                end

                S_WAIT_DECRYPT_TAG: begin
                    if (poly_done) begin
                        tag_o <= poly_tag;
                        if (tag_matches) begin
                            chacha_counter <= 32'd1;
                            chacha_start   <= 1'b1;
                            state          <= S_WAIT_DECRYPT_STREAM;
                        end else begin
                            data_o    <= '0;
                            auth_ok_o <= 1'b0;
                            busy_o    <= 1'b0;
                            done_o    <= 1'b1;
                            state     <= S_IDLE;
                        end
                    end
                end

                S_WAIT_DECRYPT_STREAM: begin
                    if (chacha_done) begin
                        data_o    <= data_reg ^ chacha_block;
                        auth_ok_o <= 1'b1;
                        busy_o    <= 1'b0;
                        done_o    <= 1'b1;
                        state     <= S_IDLE;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
