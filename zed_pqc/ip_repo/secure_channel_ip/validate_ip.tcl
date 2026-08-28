set core_dir {C:/Users/bomin/Documents/Codex/2026-08-10/new-chat/zed_pqc/ip_repo/secure_channel_ip}
set core [ipx::open_core [file join $core_dir component.xml]]
ipx::check_integrity -quiet $core
puts "IP_INTEGRITY_OK"
ipx::unload_core $core
exit
