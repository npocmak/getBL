#!/bin/bash
# ########################################################
#  Name:        getBlacklist.sh
#  Version:     1.1
#  Author:      Mad | Pavol Kluka - 2017/09/09
#  Date:        2018/10/19
#  Platforms:   Linux
# ########################################################

# SCRIPT VARIABLES
DIR_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# DATE VARIABLES
DATE_SHORT="$( date +"%Y-%m-%d" )"
DATE_LONG="$( date +"%Y-%m-%d %H:%M" )"
DATE_YESTERDAY="$( date -d "yesterday " "+%Y%m%d" )"
DATE_LOG="$( date +"%Y%m%d %H:%M:%S" )"
DATE_LIST="$( date +"%a %b %d %H:%M:%S %Z %Y" )"

# PATH VARIABLES
PATH_LIST="$DIR_SCRIPT/lists"
PATH_ARCHIVE="$DIR_SCRIPT/archive"
PATH_DATE="$PATH_ARCHIVE/$( date +"%Y%m%d" )"
PATH_BLACKLISTS="$DIR_SCRIPT/blacklists"

# BIN VARIABLES
BIN_RM="$( which rm )"
BIN_AWK="$( which awk )"
BIN_CAT="$( which cat )"
BIN_GREP="$( which grep )"
BIN_EGREP="$( which egrep )"
BIN_WGET="$( which wget )"
BIN_MKDIR="$( which mkdir )"
BIN_SED="$( which sed )"
BIN_GZIP="$( which gzip )"
BIN_CUT="$( which cut )"
BIN_TR="$( which tr )"
BIN_CD="$( which cd )"
BIN_FIND="$( which find )"
BIN_SHA1="$( which sha1sum )"

# FILE VARIABLES
FILE_IP_BLACKLIST="ip_blacklist.csv"
FILE_URL_BLACKLIST="url_blacklist.csv"
FILE_DOMAIN_BLACKLIST="domain_blacklist.csv"

# FUNCTIONS
# CHECK IF EXIST WORK FOLDER | 1st PARAMETER = FOLDER FOR CHECK
function funCheckFolder() {
    ARG1="$1"
    if [ -d "$ARG1" ]
    then
            echo "Folder $ARG1 exist."
    else
            echo "Folder $ARG1 doesn't exist. Folder was created."
            $BIN_MKDIR -p $ARG1 > /dev/null
    fi
}

function funGetTimestamp() {
    echo $(date +"%Y-%m-%d %H:%M")
}

TIMESTAMP=$( funGetTimestamp )
echo "Start ($TIMESTAMP)."

funCheckFolder $PATH_LIST
funCheckFolder $PATH_ARCHIVE
funCheckFolder $PATH_DATE
funCheckFolder $PATH_BLACKLISTS

# Reach all free Feeds
echo "Get Feodo IP Blacklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://feodotracker.abuse.ch/blocklist/?download=ipblocklist -O $PATH_DATE/ip_feodo_blocklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_feodo_blacklist.csv
echo "Processing Feodo IP Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Feodo Tracker (" var ")" }' $PATH_DATE/ip_feodo_blocklist.txt >> $PATH_LIST/ip_feodo_blacklist.csv

echo "Get Emerging Threats - Spamhaus DROP Nets."
echo "ip,description" > $PATH_LIST/ip_spamhaus_blacklist.csv
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -O $PATH_DATE/ip_spamhaus_blocklist.txt --no-check-certificate
echo "Processing Emerging Threats - Spamhaus DROP Nets ($TIMESTAMP)."
$BIN_AWK '/#.*?Spamhaus DROP Nets/ { show=1; next } /#.*?/ { show=0 } show' $PATH_DATE/ip_spamhaus_blocklist.txt | \
$BIN_AWK 'NF > 0' | \
while read IP_ADDRESS
do
  echo "$IP_ADDRESS,Spamhaus ($TIMESTAMP)" >> $PATH_LIST/ip_spamhaus_blacklist.csv
done

echo "Get DShield.org Suspicious Domain List (Low Sensitivity Level)."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://isc.sans.edu/feeds/suspiciousdomains_Low.txt -O $PATH_DATE/domain_dshield_low_blacklist.txt --no-check-certificate
echo "domain,description" > $PATH_LIST/domain_dshield_low_blacklist.csv
echo "Processing DShield.org Suspicious Domain List (Low Sensitivity Level) ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9a-zA-Z\.\-]+\.[a-z]{2,10}/ { print $1 ",DShield Suspicious Domain (Low) (" var ")" }' $PATH_DATE/domain_dshield_low_blacklist.txt >> $PATH_LIST/domain_dshield_low_blacklist.csv

echo "Get DShield.org Suspicious Domain List (Medium Sensitivity Level)."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt -O $PATH_DATE/domain_dshield_medium_blacklist.txt --no-check-certificate
echo "domain,description" > $PATH_LIST/domain_dshield_medium_blacklist.csv
echo "Processing DShield.org Suspicious Domain List (Medium Sensitivity Level) ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9a-zA-Z\.\-]+\.[a-z]{2,10}/ { print $1 ",DShield Suspicious Domain (Medium) (" var ")" }' $PATH_DATE/domain_dshield_medium_blacklist.txt >> $PATH_LIST/domain_dshield_medium_blacklist.csv

echo "Get DShield.org Suspicious Domain List (High Sensitivity Level)."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://isc.sans.edu/feeds/suspiciousdomains_High.txt -O $PATH_DATE/domain_dshield_high_blacklist.txt --no-check-certificate
echo "domain,description" > $PATH_LIST/domain_dshield_high_blacklist.csv
echo "Processing DShield.org Suspicious Domain List (High Sensitivity Level) ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9a-zA-Z\.\-]+\.[a-z]{2,10}/ { print $1 ",DShield Suspicious Domain (High) (" var ")" }' $PATH_DATE/domain_dshield_high_blacklist.txt >> $PATH_LIST/domain_dshield_high_blacklist.csv

echo "Get Emerging Threats - Known hostile or compromised hosts."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://rules.emergingthreats.net/blockrules/compromised-ips.txt -O $PATH_DATE/ip_compromised_blocklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_compromised_blacklist.csv
echo "Processing Emerging Threats - Known hostile or compromised hosts ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Compromised Host (" var ")" }' $PATH_DATE/ip_compromised_blocklist.txt >> $PATH_LIST/ip_compromised_blacklist.csv

echo "Get AlienVault - IP Reputation Database."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://reputation.alienvault.com/reputation.snort.gz -P $PATH_DATE --no-check-certificate
$BIN_GZIP -f -d $PATH_DATE/reputation.snort.gz
echo "ip,description" > $PATH_LIST/ip_snort_rep_list.csv
echo "Processing AlienVault - IP Reputation Databases ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" -F '#' '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { gsub(" ","",$1); gsub(" ","",$2); print $1 ",AlienVault Snort Reputation (" $2 ") (" var ")" }' $PATH_DATE/reputation.snort >> $PATH_LIST/ip_snort_rep_list.csv

echo "Get SSLBL - SSL Blacklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O $PATH_DATE/ip_ssl_blacklist.csv --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_ssl_blacklist.csv
echo "Processing SSL Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" -F ',' '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Abuse SSL IP Blacklist (dst_port:" $2 ") (" $3 ") (" var ")" }' $PATH_DATE/ip_ssl_blacklist.csv >> $PATH_LIST/ip_ssl_blacklist.csv

echo "Get ZeuS Tracker - IP Blacklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist -O $PATH_DATE/ip_zeus_blocklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_zeus_blacklist.csv
echo "Processing ZeuS Tracker - IP Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Abuse ZeuS IP blacklist (" var ")" }' $PATH_DATE/ip_zeus_blocklist.txt >> $PATH_LIST/ip_zeus_blacklist.csv

echo "Get Malc0de - Malc0de Blacklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://malc0de.com/bl/IP_Blacklist.txt -O $PATH_DATE/ip_malc0de_blacklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_malc0de_blacklist.csv
echo "Processing Malc0de - Malc0de Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Malc0de Blacklist (Malicious IP) (" var ")" }' $PATH_DATE/ip_malc0de_blacklist.txt >> $PATH_LIST/ip_malc0de_blacklist.csv

echo "Get IP Blacklist from Talos Reputation Center."
$BIN_WGET -q https://www.talosintelligence.com/documents/ip-blacklist -O $PATH_DATE/ip_talos_blacklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_talos_blacklist.csv
echo "Processing Talos Feeds - IP Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Cisco IP Talos Blacklist (Malicious IP flagged on all Cisco Security Products) (" var ")" }' $PATH_DATE/ip_talos_blacklist.txt >> $PATH_LIST/ip_talos_blacklist.csv

echo "Get IP Blacklist from Blocklist.de - All attacked IP addresses (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/all.txt -O $PATH_DATE/ip_blocklist_all.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_all.csv
echo "Processing Blocklist.de (All) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (All attacked IP addresses) (" var ")" }' $PATH_DATE/ip_blocklist_all.txt >> $PATH_LIST/ip_blocklist_all.csv

echo "Get IP Blacklist from Blocklist.de - Attacks on the service SSH (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/ssh.txt -O $PATH_DATE/ip_blocklist_ssh.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_ssh.csv
echo "Processing Blocklist.de (SSH) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (Attacks on the service SSH) (" var ")" }' $PATH_DATE/ip_blocklist_ssh.txt >> $PATH_LIST/ip_blocklist_ssh.csv

echo "Get IP Blacklist from Blocklist.de - Attacks on the service Mail, Postfix (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/mail.txt -O $PATH_DATE/ip_blocklist_mail.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_mail.csv
echo "Processing Blocklist.de (Attacks on the service Mail, Postfix) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (Attacks on the service Mail, Postfix) (" var ")" }' $PATH_DATE/ip_blocklist_mail.txt >> $PATH_LIST/ip_blocklist_mail.csv

echo "Get IP Blacklist from Blocklist.de - Attacks on the service Apache, Apache-DDOS, RFI-Attacks (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/apache.txt -O $PATH_DATE/ip_blocklist_apache.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_apache.csv
echo "Processing Blocklist.de (Attacks on the service Apache, Apache-DDOS, RFI-Attacks) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (Attacks on the service Apache, Apache-DDOS, RFI-Attacks) (" var ")" }' $PATH_DATE/ip_blocklist_apache.txt >> $PATH_LIST/ip_blocklist_apache.csv

echo "Get IP Blacklist from Blocklist.de - Attacks on the Service imap, sasl, pop3 (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/imap.txt -O $PATH_DATE/ip_blocklist_imap.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_imap.csv
echo "Processing Blocklist.de (Attacks on the Service imap, sasl, pop3) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (Attacks on the Service imap, sasl, pop3) (" var ")" }' $PATH_DATE/ip_blocklist_imap.txt >> $PATH_LIST/ip_blocklist_imap.csv

echo "Get IP Blacklist from Blocklist.de - Attacks on the Service FTP (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/ftp.txt -O $PATH_DATE/ip_blocklist_ftp.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_ftp.csv
echo "Processing Blocklist.de (Attacks on the Service FTP) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (Attacks on the Service FTP) (" var ")" }' $PATH_DATE/ip_blocklist_ftp.txt >> $PATH_LIST/ip_blocklist_ftp.csv

echo "Get IP Blacklist from Blocklist.de - All IP addresses that tried to login in a SIP-, VOIP- or Asterisk-Server (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/sip.txt -O $PATH_DATE/ip_blocklist_sip.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_sip.csv
echo "Processing Blocklist.de (SIP) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (All IP addresses that tried to login in a SIP-, VOIP- or Asterisk-Server) (" var ")" }' $PATH_DATE/ip_blocklist_sip.txt >> $PATH_LIST/ip_blocklist_sip.csv

echo "Get IP Blacklist from Blocklist.de - Attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/bots.txt -O $PATH_DATE/ip_blocklist_bots.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_bots.csv
echo "Processing Blocklist.de (BOTs) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (Attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots) (" var ")" }' $PATH_DATE/ip_blocklist_bots.txt >> $PATH_LIST/ip_blocklist_bots.csv

echo "Get IP Blacklist from Blocklist.de - All IPs which are older then 2 month and have more then 5.000 attacks."
$BIN_WGET -q https://lists.blocklist.de/lists/strongips.txt -O $PATH_DATE/ip_blocklist_strongips.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_strongips.csv
echo "Processing Blocklist.de (STRONG IPs) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (All IPs which are older then 2 month and have more then 5.000 attacks) (" var ")" }' $PATH_DATE/ip_blocklist_strongips.txt >> $PATH_LIST/ip_blocklist_strongips.csv

echo "Get IP Blacklist from Blocklist.de - All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Loginss (last 48 hours)."
$BIN_WGET -q https://lists.blocklist.de/lists/bruteforcelogin.txt -O $PATH_DATE/ip_blocklist_bruteforcelogin.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_blocklist_bruteforcelogin.csv
echo "Processing Blocklist.de (BRUTE FORCE LOGIN) - IP Blacklist"
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Blocklist.de IP Blacklist (All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Logins) (" var ")" }' $PATH_DATE/ip_blocklist_bruteforcelogin.txt >> $PATH_LIST/ip_blocklist_bruteforcelogin.csv

echo "Get Ransomware Tracker - Ransomware IP Blacklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt -O $PATH_DATE/ip_ransomtracker_blacklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_ransomtracker_blacklist.csv
echo "Processing Ransomware Tracker - Ransomware IP Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Ransomware Tracker IP Blocklist (" var ")" }' $PATH_DATE/ip_ransomtracker_blacklist.txt >> $PATH_LIST/ip_ransomtracker_blacklist.csv

echo "Get Ransomware Tracker - Ransomware Domain BlAcklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt -O $PATH_DATE/domain_ransomtracker_blacklist.txt --no-check-certificate
echo "domain,description" > $PATH_LIST/domain_ransomtracker_blacklist.csv
echo "Processing Ransomware Tracker - Ransomware Domain Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9a-zA-Z\.\-]+\.[a-z]{2,10}/ { print $1 ",Ransomware Domain Blacklist (" var ")" }' $PATH_DATE/domain_ransomtracker_blacklist.txt >> $PATH_LIST/domain_ransomtracker_blacklist.csv

echo "Get Ransomware Tracker - Ransomware URL Blacklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt -O $PATH_DATE/url_ransomtracker_blacklist.txt --no-check-certificate
echo "url,description" > $PATH_LIST/url_ransomtracker_blacklist.csv
echo "Processing Ransomware Tracker - Ransomware URL Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9a-zA-Z\.\:\/\W\S]+\.[a-z]{2,10}/ { print $1 ",Ransomware Domain Blacklist (" var ")" }' $PATH_DATE/url_ransomtracker_blacklist.txt >> $PATH_LIST/url_ransomtracker_blacklist.csv

echo "Get Threatexpert.com Malicious Domains."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://www.networksec.org/grabbho/block.txt -O $PATH_DATE/domain_threatexpert_blacklist.txt --no-check-certificate
echo "domain,description" > $PATH_LIST/domain_threatexpert_blacklist.csv
echo "Processing Threatexpert.com Malicious Domain ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/^[0-9a-zA-Z\.\:\/\W\S]+\.[a-z]{2,10}/ { print $1 ",Threatexpert.com Malicious Domain (" var ")" }' $PATH_DATE/domain_threatexpert_blacklist.txt >> $PATH_LIST/domain_threatexpert_blacklist.csv

echo "Get Bambenek's Feed of known, active and non-sinkholed C&Cs IP addresses."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt -O $PATH_DATE/ip_bambeneks_blacklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_bambeneks_blacklist.csv
echo "Processing Bambenek's Master Feed of active C&C IP addresses ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" -F ',' '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Bambeneks C&Cs IP addresses (Who: " $2 ") (When: " $3 ") (Detail: " $4 ") (" var ")" }' $PATH_DATE/ip_bambeneks_blacklist.txt >> $PATH_LIST/ip_bambeneks_blacklist.csv

echo "Get BotScout FireHOL IP List."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://botscout.com/last_caught_cache.txt -O $PATH_DATE/ip_botscout_blacklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_botscout_blacklist.csv
echo "Processing BotScout FireHOL IP List with email addresses of Bots ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" -F ',' '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { if( $2 ~ "a href" ) print $3 ",BotScout FireHOL IP addresses (BotName: " $1 ") (BotEmail: Unknown) (" var ")"; else print $3 ",BotScout FireHOL IP addresses (BotName: " $1 ") (BotEmail: " $2 ") (" var ")" }' $PATH_DATE/ip_botscout_blacklist.txt >> $PATH_LIST/ip_botscout_blacklist.csv

echo "Get Brute Force Blocker IP List."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://danger.rulez.sk/projects/bruteforceblocker/blist.php -O $PATH_DATE/ip_bruteforce_blacklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_bruteforce_blacklist.csv
echo "Processing Brute Force Blocker IP List ($TIMESTAMP)."
$BIN_AWK '/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",Brute Force Blocker IP List (Last Reported: " $3 ") (Count:" $5 ") (" var ")" }' $PATH_DATE/ip_bruteforce_blacklist.txt >> $PATH_LIST/ip_bruteforce_blacklist.csv

echo "Get CI Army Bad IPs."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://www.ciarmy.com/list/ci-badguys.txt -O $PATH_DATE/ip_badguys_blacklist.txt --no-check-certificate
echo "ip,description" > $PATH_LIST/ip_badguys_blacklist.csv
echo "Processing CI Army Bad IPs ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ { print $1 ",CI Army Bad IPs (" var ")" }' $PATH_DATE/ip_badguys_blacklist.txt >> $PATH_LIST/ip_badguys_blacklist.csv

echo "Get Malware Domain Blacklist."
# TIMESTAMP=$( funGetTimestamp )
$BIN_WGET -q http://mirror1.malwaredomains.com/files/domains.txt -O $PATH_DATE/domain_malware_blacklist.txt --no-check-certificate
echo "domain,description" > $PATH_LIST/domain_malware_blacklist.csv
echo "Processing Malware Domain Blacklist ($TIMESTAMP)."
$BIN_AWK -v var="$TIMESTAMP" '/[0-9a-zA-Z\.\-]+\.[a-z]{2,10}/ { print $1 ",Malware Domain Blacklist (Category: " $2 ") (Source: " $3 ") (" var ")" }' $PATH_DATE/domain_malware_blacklist.txt >> $PATH_LIST/domain_malware_blacklist.csv

# Collect all feeds to one csv per type of feeds
# TIMESTAMP=$( funGetTimestamp )
echo "Collecting tables to blacklist folder ($TIMESTAMP)."
echo "ip,description" > $PATH_BLACKLISTS/$FILE_IP_BLACKLIST
$BIN_FIND $PATH_LIST -type f -name "ip_*" | \
while read TABLE
do
  $BIN_GREP -v "ip,description" $TABLE >> $PATH_BLACKLISTS/$FILE_IP_BLACKLIST
done

echo "domain,description" > $PATH_BLACKLISTS/$FILE_DOMAIN_BLACKLIST
$BIN_FIND $PATH_LIST -type f -name "domain_*" | \
while read TABLE
do
  $BIN_GREP -v "domain,description" $TABLE >> $PATH_BLACKLISTS/$FILE_DOMAIN_BLACKLIST
done

echo "url,description" > $PATH_BLACKLISTS/$FILE_URL_BLACKLIST
$BIN_FIND $PATH_LIST -type f -name "url_*" | \
while read TABLE
do
  $BIN_GREP -v "url,description" $TABLE >> $PATH_BLACKLISTS/$FILE_URL_BLACKLIST
done

# TIMESTAMP=$( funGetTimestamp )
echo "End ($TIMESTAMP)."
