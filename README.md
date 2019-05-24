Mikrotik IP blocking
This project is designed to run OS X server 10.6 (Snow Leopard) mail server.

It works in conjunction with a Mikrotik router (RouterOS) to detect unauthorised SASL login attempts and block their IP's for a specified period of time.

**Important:**

Adjust configuration parameters in *mtik_add_ip.pl* to suit your environment.

**File locations:**

`/usr/share/mtik/`:

    mikrotik.hs
    mtik_add_ip.pl
    Mtik.pm

`/Library/LaunchDaemons/`:

    com.contech.mikrotik.plist

Start:
`launchctl load /Library/LaunchDaemons/com.contech.mikrotik.plist` 

Check:
`launchctl list | grep mikrotik`

Stop:
`launchctl unload /Library/LaunchDaemons/com.contech.mikrotik.plist` 
