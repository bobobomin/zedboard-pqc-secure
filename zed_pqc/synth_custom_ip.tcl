set root "C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/zed_pqc"
open_project [file join $root project_1 project_1.xpr]
update_ip_catalog -rebuild
config_ip_cache -disable_cache
set ip [get_ips -quiet system_mlkem_secure_channel_0_0]
puts "CUSTOM_IP=$ip"
if {[llength $ip] != 1} { error "Custom IP not found" }
synth_ip -force $ip
puts "CUSTOM_IP_DCP=[get_property IP_USER_FILES [get_ips system_mlkem_secure_channel_0_0]]"
close_project
