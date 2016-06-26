<?php
$mod_name="detectdeauth";
$mod_version="1.0";
$mod_path="/usr/share/fruitywifi/www/modules/$mod_name";
$mod_logs="$log_path/$mod_name.log"; 
$mod_logs_history="$mod_path/includes/logs/";
$mod_panel="show";
$mod_type="service";
$mod_alias="DetectDeauth";

# OPTIONS
$mod_detectdeauth_vigilant="1";
$mod_detectdeauth_karma="1";
$mod_detectdeauth_alert="0";
$mod_detectdeauth_alert_delay="5";
$mod_detectdeauth_number="20";
$mod_detectdeauth_smtp_server="localhost";
$mod_detectdeauth_smtp_port="25";
$mod_detectdeauth_smtp_user="";
$mod_detectdeauth_smtp_pass="";
$mod_detectdeauth_smtp_auth="0";
$mod_detectdeauth_smtp_starttls="0";
$mod_detectdeauth_email_from="";
$mod_detectdeauth_email_to="";
$mod_detectdeauth_channel="1,2,3,4,5,6,7,8,9,10,11,12";
$mod_detectdeauth_jump="1";

# EXEC
$bin_sudo = "/usr/bin/sudo";
$bin_iptables = "/sbin/iptables";
$bin_awk = "/usr/bin/awk";
$bin_grep = "/bin/grep";
$bin_sed = "/bin/sed";
$bin_cat = "/bin/cat";
$bin_echo = "/bin/echo";
$bin_ln = "/bin/ln";
$bin_arp = "/usr/sbin/arp";
$bin_rm = "/bin/rm";
$bin_cp = "/bin/cp";

# ISUP
$mod_isup="ps auxww | grep -iEe 'scan-deauth' | grep -v -e grep";
?>
