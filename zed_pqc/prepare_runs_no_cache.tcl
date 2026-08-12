set root "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/zed_pqc"
open_project [file join $root project_1 project_1.xpr]
update_ip_catalog -rebuild
config_ip_cache -disable_cache
set bd_file [get_files -quiet */system.bd]
reset_target all $bd_file
generate_target -force all $bd_file
create_ip_run $bd_file
reset_run synth_1
reset_run impl_1
save_project
close_project
