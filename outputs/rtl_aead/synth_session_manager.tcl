set root_dir "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/outputs/rtl_aead"
set num_sessions 64
if {$argc >= 1} {
    set num_sessions [lindex $argv 0]
}
if {$num_sessions == 32} {
    set slot_width 5
} elseif {$num_sessions == 64} {
    set slot_width 6
} else {
    error "synth_session_manager.tcl supports NUM_SESSIONS=32 or 64"
}

set_param general.maxThreads 2
read_verilog -sv [file join $root_dir rtl chacha20_block.sv]
read_verilog -sv [file join $root_dir rtl poly1305_fixed96.sv]
read_verilog -sv [file join $root_dir rtl aead_fixed64_engine.sv]
read_verilog -sv [file join $root_dir rtl aead_session_manager_bram.sv]

synth_design -top aead_session_manager_bram -part xc7z020clg484-1 \
    -generic "NUM_SESSIONS=$num_sessions SLOT_WIDTH=$slot_width"

report_utilization -hierarchical -hierarchical_depth 3 \
    -file [file join $root_dir "utilization_session_${num_sessions}.rpt"]
report_timing_summary \
    -file [file join $root_dir "timing_session_${num_sessions}.rpt"]
report_ram_utilization \
    -file [file join $root_dir "ram_session_${num_sessions}.rpt"]

set bram_cells [get_cells -hierarchical -filter {PRIMITIVE_TYPE =~ BMEM.*}]
puts "SESSION_SYNTH NUM_SESSIONS=$num_sessions SLOT_WIDTH=$slot_width BRAM_CELLS=[llength $bram_cells]"
foreach cell $bram_cells {
    puts "SESSION_BRAM $cell [get_property PRIMITIVE_TYPE $cell]"
}
