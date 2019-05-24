#! /bin/sh
#
# monitor for SASL login authentication failure
# and block offending IP's on Mikrotik router
#
# for runnign as a Daemon (via launchctl)
/usr/bin/tail -F /var/log/mail.log | /usr/bin/grep --line-buffered "SASL" | /usr/bin/sed -El 's/.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*/\1 attackers/' | /usr/share/mtik/mtik_add_ip.pl
#
# put in background when launched from command line:
#/usr/bin/tail -F /var/log/mail.log | /usr/bin/grep --line-buffered "SASL" | /usr/bin/sed -El 's/.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*/\1 attackers/' | /usr/share/mtik/mtik_add_ip.pl &
# for testing:
#/usr/bin/tail -n5000 -F /var/log/mail.log | /usr/bin/grep --line-buffered "SASL" | /usr/bin/sed -El 's/.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*/\1 attackers/'
