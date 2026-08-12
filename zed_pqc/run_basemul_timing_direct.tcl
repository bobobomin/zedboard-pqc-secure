set root "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/zed_pqc"
set report_dir [file join $root timing_results_direct]
file mkdir $report_dir
set_param general.maxThreads 4

open_project [file join $root project_1 project_1.xpr]
update_ip_catalog -rebuild
set bd_file [get_files -quiet */system.bd]
if {[llength $bd_file] != 1} {
    error "Expected exactly one system.bd, found [llength $bd_file]"
}
generate_target all $bd_file

# Run in memory to avoid the Windows project-run child-process launcher.
synth_design -top system_wrapper -part xc7z020clg484-1
write_checkpoint -force [file join $report_dir post_synth.dcp]
report_utilization -file [file join $report_dir utilization_post_synth.rpt]

opt_design
place_design
phys_opt_design
route_design
write_checkpoint -force [file join $report_dir post_route.dcp]

report_utilization -hierarchical -hierarchical_depth 7 \
    -file [file join $report_dir utilization_hierarchical.rpt]
report_timing_summary -file [file join $report_dir timing_summary.rpt]
report_timing -delay_type max -max_paths 100 -nworst 1 -sort_by group \
    -path_type full -file [file join $report_dir worst_setup_100.rpt]

set setup_path [get_timing_paths -delay_type max -max_paths 1]
set hold_path [get_timing_paths -delay_type min -max_paths 1]
puts "FINAL_WNS_NS=[get_property SLACK $setup_path]"
puts "FINAL_WHS_NS=[get_property SLACK $hold_path]"
puts "SETUP_STARTPOINT=[get_property STARTPOINT_PIN $setup_path]"
puts "SETUP_ENDPOINT=[get_property ENDPOINT_PIN $setup_path]"

close_project
