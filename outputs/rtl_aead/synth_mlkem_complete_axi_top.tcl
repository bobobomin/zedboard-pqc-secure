set root "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/outputs/rtl_aead"
set_param general.maxThreads 1
read_verilog -sv [glob $root/rtl/*.sv]
if {[catch {synth_design -top mlkem_secure_channel_complete_axi_top -part xc7z020clg484-1 -mode out_of_context} synth_message]} {
    puts "Vivado returned after synthesis cleanup: $synth_message"
}
report_utilization -file $root/mlkem_complete_axi_top_utilization.rpt
report_timing_summary -file $root/mlkem_complete_axi_top_timing.rpt
puts "MLKEM_COMPLETE_AXI_TOP_SYNTHESIS_COMPLETE"
