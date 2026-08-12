set root_dir "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/outputs/rtl_aead"
set_param general.maxThreads 1
read_verilog -sv [file join $root_dir rtl mlkem_poly_accelerator.sv]
if {[catch {synth_design -top mlkem_poly_accelerator -part xc7z020clg484-1} synth_message]} {
    puts "Vivado returned after synthesis cleanup: $synth_message"
}
report_utilization -file [file join $root_dir utilization_mlkem_poly.rpt]
report_timing_summary -file [file join $root_dir timing_mlkem_poly.rpt]
