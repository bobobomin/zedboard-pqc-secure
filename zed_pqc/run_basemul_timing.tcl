set script_dir "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/zed_pqc"
set project_file [file join $script_dir project_1 project_1.xpr]
set report_dir [file join $script_dir timing_results]
file mkdir $report_dir

open_project $project_file
update_ip_catalog -rebuild

set bd_file [get_files -quiet */system.bd]
if {[llength $bd_file] != 1} {
    error "Expected exactly one system.bd, found [llength $bd_file]"
}

# Force Vivado to rebuild the packaged-IP copy and every dependent OOC DCP.
reset_target all $bd_file
generate_target all $bd_file
export_ip_user_files -of_objects $bd_file -no_script -sync -force -quiet

foreach run [get_runs -quiet *_synth_1] {
    reset_run $run
}
reset_run synth_1
reset_run impl_1

launch_runs synth_1 -jobs 4
wait_on_run synth_1
set synth_status [get_property STATUS [get_runs synth_1]]
puts "SYNTH_STATUS=$synth_status"
if {![string match "*Complete*" $synth_status]} {
    error "Synthesis did not complete: $synth_status"
}

launch_runs impl_1 -jobs 4
wait_on_run impl_1
set impl_status [get_property STATUS [get_runs impl_1]]
puts "IMPL_STATUS=$impl_status"
if {![string match "*Complete*" $impl_status]} {
    error "Implementation did not complete: $impl_status"
}

open_run impl_1
report_utilization -hierarchical -hierarchical_depth 7 \
    -file [file join $report_dir utilization_hierarchical.rpt]
report_timing_summary -file [file join $report_dir timing_summary.rpt]
report_timing -delay_type max -max_paths 100 -nworst 1 -sort_by group \
    -path_type full -file [file join $report_dir worst_setup_100.rpt]

set wns [get_property SLACK [get_timing_paths -delay_type max -max_paths 1]]
set whs [get_property SLACK [get_timing_paths -delay_type min -max_paths 1]]
puts "FINAL_WNS_NS=$wns"
puts "FINAL_WHS_NS=$whs"

close_project
