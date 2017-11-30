# Bash
All my scripts written in Bourne again shell.

## getBlacklist.sh
This script download list of IP addresses, URL and domains, which are suspicious or maicious.
List of sources:
1. **Feodo IP Blacklist**
* https://feodotracker.abuse.ch/blocklist/?download=ipblocklist
2. **Emerging Threats - Spamhaus DROP Nets**
* http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
3. **DShield.org Suspicious Domain List (Low Sensitivity Level)**
* https://isc.sans.edu/feeds/suspiciousdomains_Low.txt
4. **DShield.org Suspicious Domain List (Medium Sensitivity Level)**
* https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt
5. **DShield.org Suspicious Domain List (High Sensitivity Level)**
* https://isc.sans.edu/feeds/suspiciousdomains_High.txt
6. **Emerging Threats - Known hostile or compromised hosts**
* http://rules.emergingthreats.net/blockrules/compromised-ips.txt
7. **Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed**
* http://www.binarydefense.com/banlist.txt
8. **AlienVault - IP Reputation Database**
* https://reputation.alienvault.com/reputation.snort.gz
9. **SSLBL - SSL Blacklist**
* https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
10. **ZeuS Tracker - IP Blacklist**
* https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist
11. **Malc0de - Malc0de Blacklist**
* http://malc0de.com/bl/IP_Blacklist.txt
12. **Ransomware Tracker - Ransomware IP Blacklist**
* https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt
13. **Ransomware Tracker - Ransomware Domain Blacklist**
* https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt
14. **Ransomware Tracker - Ransomware URL Blacklist**
* https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt
15. **Threatexpert.com Malicious Domains**
* http://www.networksec.org/grabbho/block.txt
16. **Bambenek's Feed of known, active and non-sinkholed C&Cs IP addresses**
* http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt
17. **BotScout FireHOL IP List**
* http://botscout.com/last_caught_cache.txt
18. **Brute Force Blocker IP List**
* http://danger.rulez.sk/projects/bruteforceblocker/blist.php
19. **CI Army Bad IPs**
* http://www.ciarmy.com/list/ci-badguys.txt
20. **Malware Domain Blacklist**
* http://mirror1.malwaredomains.com/files/domains.txt
21. **Talos Reputation Center**
* https://www.talosintelligence.com/documents/ip-blacklist
22. **Talos Reputation Center**
* https://www.talosintelligence.com/documents/ip-blacklist
23. **Blocklist.de - All attacked IP addresses**
* https://lists.blocklist.de/lists/all.txt
24. **Blocklist.de - Attacks on the service SSH**
* https://lists.blocklist.de/lists/ssh.txt
25. **Blocklist.de - Attacks on the service Mail, Postfix**
* https://lists.blocklist.de/lists/mail.txt
26. **Blocklist.de - Attacks on the service Apache, Apache-DDOS, RFI-Attacks**
* https://lists.blocklist.de/lists/apache.txt
27. **Blocklist.de - Attacks on the Service imap, sasl, pop3**
* https://lists.blocklist.de/lists/imap.txt
28. **Blocklist.de - Attacks on the Service FTP**
* https://lists.blocklist.de/lists/ftp.txt
29. **Blocklist.de - All IP addresses that tried to login in a SIP-, VOIP- or Asterisk-Server**
* https://lists.blocklist.de/lists/sip.txt
30. **Blocklist.de - Attacks attacks on the RFI-Attacks, REG-Bots, IRC-Bots or BadBots**
https://lists.blocklist.de/lists/bots.txt
31. **Blocklist.de - All IPs which are older then 2 month and have more then 5.000 attacks**
* https://lists.blocklist.de/lists/strongips.txt
32. **All IPs which attacks Joomlas, Wordpress and other Web-Logins with Brute-Force Loginss**
* https://lists.blocklist.de/lists/bruteforcelogin.txt
