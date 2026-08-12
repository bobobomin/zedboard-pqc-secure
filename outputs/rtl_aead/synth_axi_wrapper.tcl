set root_dir "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/outputs/rtl_aead"
set_param general.maxThreads 1
read_verilog -sv [file join $root_dir rtl chacha20_block.sv]
read_verilog -sv [file join $root_dir rtl poly1305_fixed96.sv]
read_verilog -sv [file join $root_dir rtl aead_fixed64_engine.sv]
read_verilog -sv [file join $root_dir rtl aead_arbiter_4session.sv]
read_verilog -sv [file join $root_dir rtl keccak_f1600.sv]
read_verilog -sv [file join $root_dir rtl sha3_shake_stream.sv]
read_verilog -sv [file join $root_dir rtl mlkem_session_kdf.sv]
read_verilog -sv [file join $root_dir rtl aead_axi_lite_wrapper.sv]

if {[catch {synth_design -top aead_axi_lite_wrapper -part xc7z020clg484-1} synth_message]} {
    puts "Vivado returned after synthesis cleanup: $synth_message"
}
report_utilization -file [file join $root_dir utilization_axi_wrapper.rpt]
report_timing_summary -file [file join $root_dir timing_axi_wrapper.rpt]
