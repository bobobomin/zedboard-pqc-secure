$ErrorActionPreference = 'Stop'

$VivadoBin = 'C:\Xilinx\Vivado\2020.2\bin'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Work = Join-Path $Root 'xsim_work'

New-Item -ItemType Directory -Force -Path $Work | Out-Null
Push-Location $Work
try {
    & (Join-Path $VivadoBin 'xvlog.bat') -sv `
        (Join-Path $Root 'rtl\chacha20_block.sv') `
        (Join-Path $Root 'rtl\poly1305_fixed96.sv') `
        (Join-Path $Root 'rtl\aead_fixed64_wrapper.sv') `
        (Join-Path $Root 'rtl\aead_fixed64_decrypt_wrapper.sv') `
        (Join-Path $Root 'rtl\aead_fixed64_engine.sv') `
        (Join-Path $Root 'rtl\aead_arbiter_4session.sv') `
        (Join-Path $Root 'rtl\aead_axi_lite_wrapper.sv') `
        (Join-Path $Root 'rtl\keccak_f1600.sv') `
        (Join-Path $Root 'rtl\sha3_shake_stream.sv') `
        (Join-Path $Root 'rtl\mlkem_poly_accelerator.sv') `
        (Join-Path $Root 'rtl\mlkem_session_kdf.sv') `
        (Join-Path $Root 'rtl\secure_channel_core.sv') `
        (Join-Path $Root 'rtl\mlkem512_codec_primitives.sv') `
        (Join-Path $Root 'rtl\mlkem512_sampling_primitives.sv') `
        (Join-Path $Root 'rtl\mlkem_decaps_memory.sv') `
        (Join-Path $Root 'rtl\mlkem512_unpack_controller.sv') `
        (Join-Path $Root 'rtl\mlkem_poly_bridge_controller.sv') `
        (Join-Path $Root 'rtl\mlkem_poly_addsub_controller.sv') `
        (Join-Path $Root 'rtl\mlkem512_kpke_decrypt_engine.sv') `
        (Join-Path $Root 'rtl\mlkem_decaps_axi_lite_frontend.sv') `
        (Join-Path $Root 'rtl\mlkem_hash_g.sv') `
        (Join-Path $Root 'rtl\mlkem_matrix_poly_generator.sv') `
        (Join-Path $Root 'rtl\mlkem_noise_poly_generator.sv') `
        (Join-Path $Root 'rtl\mlkem512_decaps_aux_controllers.sv') `
        (Join-Path $Root 'rtl\mlkem512_kpke_reencrypt_engine.sv') `
        (Join-Path $Root 'rtl\mlkem512_decaps_engine.sv') `
        (Join-Path $Root 'rtl\mlkem_handshake_transcript_hash.sv') `
        (Join-Path $Root 'rtl\mlkem_secure_channel_axi_top.sv') `
        (Join-Path $Root 'rtl\mlkem_shared_hash_engine.sv') `
        (Join-Path $Root 'rtl\mlkem512_kpke_reencrypt_shared_engine.sv') `
        (Join-Path $Root 'rtl\mlkem512_decaps_shared_engine.sv') `
        (Join-Path $Root 'rtl\secure_channel_material_core.sv') `
        (Join-Path $Root 'rtl\mlkem_secure_channel_shared_axi_top.sv') `
        (Join-Path $Root 'rtl\mlkem_secure_channel_fault_protected_axi_top.sv') `
        (Join-Path $Root 'rtl\aead_traffic_axi_lite_frontend.sv') `
        (Join-Path $Root 'rtl\mlkem_secure_channel_complete_axi_top.sv') `
        (Join-Path $Root 'tb\tb_aead_arbiter_4session.sv') `
        (Join-Path $Root 'tb\tb_aead_axi_lite_wrapper.sv') `
        (Join-Path $Root 'tb\tb_aead_fixed64.sv') `
        (Join-Path $Root 'tb\tb_sha3_shake_stream.sv') `
        (Join-Path $Root 'tb\tb_mlkem_poly_accelerator.sv') `
        (Join-Path $Root 'tb\tb_secure_channel_core.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_codec_primitives.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_sampling_primitives.sv') `
        (Join-Path $Root 'tb\tb_mlkem_decaps_memory.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_unpack_controller.sv') `
        (Join-Path $Root 'tb\tb_mlkem_poly_bridge_controller.sv') `
        (Join-Path $Root 'tb\tb_mlkem_decaps_axi_frontend.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_kpke_decrypt_engine.sv') `
        (Join-Path $Root 'tb\tb_mlkem_hash_g.sv') `
        (Join-Path $Root 'tb\tb_mlkem_matrix_poly_generator.sv') `
        (Join-Path $Root 'tb\tb_mlkem_noise_poly_generator.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_decaps_aux.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_kpke_reencrypt_engine.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_decaps_engine.sv') `
        (Join-Path $Root 'tb\tb_mlkem_handshake_transcript_hash.sv') `
        (Join-Path $Root 'tb\tb_mlkem_secure_channel_axi_top.sv') `
        (Join-Path $Root 'tb\tb_mlkem_shared_hash_engine.sv') `
        (Join-Path $Root 'tb\tb_mlkem512_decaps_shared_engine.sv') `
        (Join-Path $Root 'tb\tb_mlkem_secure_channel_shared_axi_top.sv') `
        (Join-Path $Root 'tb\tb_full_attack_fault_protection.sv') `
        (Join-Path $Root 'tb\tb_mlkem_secure_channel_complete_axi_top.sv')
    if ($LASTEXITCODE -ne 0) { throw 'xvlog failed' }

    & (Join-Path $VivadoBin 'xelab.bat') tb_aead_fixed64 -s tb_aead_fixed64_sim
    if ($LASTEXITCODE -ne 0) { throw 'xelab failed' }

    & (Join-Path $VivadoBin 'xsim.bat') tb_aead_fixed64_sim -runall
    if ($LASTEXITCODE -ne 0) { throw 'xsim failed' }

    & (Join-Path $VivadoBin 'xelab.bat') tb_aead_arbiter_4session -s tb_aead_arbiter_sim
    if ($LASTEXITCODE -ne 0) { throw 'arbiter xelab failed' }

    & (Join-Path $VivadoBin 'xsim.bat') tb_aead_arbiter_sim -runall
    if ($LASTEXITCODE -ne 0) { throw 'arbiter xsim failed' }

    & (Join-Path $VivadoBin 'xelab.bat') tb_aead_axi_lite_wrapper -s tb_aead_axi_sim
    if ($LASTEXITCODE -ne 0) { throw 'AXI xelab failed' }

    & (Join-Path $VivadoBin 'xsim.bat') tb_aead_axi_sim -runall
    if ($LASTEXITCODE -ne 0) { throw 'AXI xsim failed' }

    & (Join-Path $VivadoBin 'xelab.bat') tb_sha3_shake_stream -s tb_sha3_shake_sim
    if ($LASTEXITCODE -ne 0) { throw 'SHA3 xelab failed' }

    & (Join-Path $VivadoBin 'xsim.bat') tb_sha3_shake_sim -runall
    if ($LASTEXITCODE -ne 0) { throw 'SHA3 xsim failed' }

    & (Join-Path $VivadoBin 'xelab.bat') tb_mlkem_poly_accelerator -s tb_mlkem_poly_sim
    if ($LASTEXITCODE -ne 0) { throw 'ML-KEM polynomial xelab failed' }

    & (Join-Path $VivadoBin 'xsim.bat') tb_mlkem_poly_sim -runall
    if ($LASTEXITCODE -ne 0) { throw 'ML-KEM polynomial xsim failed' }

    & (Join-Path $VivadoBin 'xelab.bat') tb_secure_channel_core -s tb_secure_channel_sim
    if ($LASTEXITCODE -ne 0) { throw 'secure-channel xelab failed' }

    & (Join-Path $VivadoBin 'xsim.bat') tb_secure_channel_sim -runall
    if ($LASTEXITCODE -ne 0) { throw 'secure-channel xsim failed' }

    $ExtraTests = @(
        @('tb_mlkem512_codec_primitives','tb_mlkem_codec_sim'),
        @('tb_mlkem512_sampling_primitives','tb_mlkem_sampling_sim'),
        @('tb_mlkem_decaps_memory','tb_mlkem_mem_sim'),
        @('tb_mlkem512_unpack_controller','tb_mlkem_unpack_sim'),
        @('tb_mlkem_poly_bridge_controller','tb_mlkem_bridge_sim'),
        @('tb_mlkem_decaps_axi_frontend','tb_mlkem_axi_front_sim'),
        @('tb_mlkem512_kpke_decrypt_engine','tb_kpke_dec_sim'),
        @('tb_mlkem_hash_g','tb_mlkem_hashg_sim'),
        @('tb_mlkem_matrix_poly_generator','tb_matrix_sim'),
        @('tb_mlkem_noise_poly_generator','tb_noise_sim'),
        @('tb_mlkem512_decaps_aux','tb_aux_sim'),
        @('tb_mlkem512_kpke_reencrypt_engine','tb_reenc_sim'),
        @('tb_mlkem512_decaps_engine','tb_decaps_sim'),
        @('tb_mlkem_handshake_transcript_hash','tb_th_sim'),
        @('tb_mlkem_secure_channel_axi_top','tb_axi_secure_sim'),
        @('tb_mlkem_shared_hash_engine','tb_shared_hash_sim'),
        @('tb_mlkem512_decaps_shared_engine','tb_decaps_shared_sim'),
        @('tb_mlkem_secure_channel_shared_axi_top','tb_axi_shared_secure_sim'),
        @('tb_full_attack_fault_protection','tb_full_attack_sim'),
        @('tb_mlkem_secure_channel_complete_axi_top','tb_complete_axi_sim')
    )
    foreach ($Test in $ExtraTests) {
        & (Join-Path $VivadoBin 'xelab.bat') $Test[0] -s $Test[1]
        if ($LASTEXITCODE -ne 0) { throw "$($Test[0]) xelab failed" }
        & (Join-Path $VivadoBin 'xsim.bat') $Test[1] -runall
        if ($LASTEXITCODE -ne 0) { throw "$($Test[0]) xsim failed" }
    }
}
finally {
    Pop-Location
}
