`timescale 1ns/1ps
module tb_mlkem512_codec_primitives;
    logic [39:0] d10_bytes,d10_roundtrip;logic [63:0] d10_coeffs;
    logic [7:0] d4_byte,d4_roundtrip;logic [31:0] d4_coeffs;
    logic [23:0] b12,b12_roundtrip;logic [31:0] c12;
    logic [7:0] msg,msg_back;logic [127:0] msg_coeffs;
    integer i;
    mlkem_decompress_d10_group a(d10_bytes,d10_coeffs);
    mlkem_compress_d10_group b(d10_coeffs,d10_roundtrip);
    mlkem_decompress_d4_group c(d4_byte,d4_coeffs);
    mlkem_compress_d4_group d(d4_coeffs,d4_roundtrip);
    mlkem_decode12_group e(b12,c12);mlkem_encode12_group f(c12,b12_roundtrip);
    mlkem_message_group g(msg,msg_coeffs,msg_coeffs,msg_back);
    initial begin
        /* First ten bytes of the deterministic ML-KEM-512 ciphertext. */
        d10_bytes=40'h870a876fd5;#1;
        if(d10_coeffs!==64'h06dc022206080c75)$fatal(1,"d10 group0 %h",d10_coeffs);
        if(d10_roundtrip!==d10_bytes)$fatal(1,"d10 roundtrip");
        d10_bytes=40'ha1e736dad0;#1;
        if(d10_coeffs!==64'h083707f605900925)$fatal(1,"d10 group1 %h",d10_coeffs);
        if(d10_roundtrip!==d10_bytes)$fatal(1,"d10 roundtrip2");
        for(i=0;i<256;i=i+1)begin d4_byte=i;#1;
            if(d4_roundtrip!==d4_byte)$fatal(1,"d4 roundtrip %0d",i);end
        b12=24'habc123;#1;if(c12!==32'h0abc0123||b12_roundtrip!==b12)
            $fatal(1,"12-bit codec");
        for(i=0;i<256;i=i+1)begin msg=i;#1;
            if(msg_back!==msg)$fatal(1,"message conversion %0d",i);end
        $display("ALL ML-KEM-512 CODEC PRIMITIVE TESTS PASSED");$finish;
    end
endmodule
