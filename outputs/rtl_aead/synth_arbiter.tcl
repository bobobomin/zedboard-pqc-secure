set root_dir "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/outputs/rtl_aead"
set_param general.maxThreads 1
read_verilog -sv [file join $root_dir rtl chacha20_block.sv]
read_verilog -sv [file join $root_dir rtl poly1305_fixed96.sv]
read_verilog -sv [file join $root_dir rtl aead_fixed64_engine.sv]
read_verilog -sv [file join $root_dir rtl aead_arbiter_4session.sv]

synth_design -top aead_arbiter_4session -part xc7z020clg484-1
report_utilization -file [file join $root_dir utilization_arbiter.rpt]
report_timing_summary -file [file join $root_dir timing_arbiter.rpt]
