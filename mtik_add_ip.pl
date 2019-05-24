#!/usr/bin/perl -w
#
###############################################################################
# File: mtik_add_ip.pl
#
# Short description: Add an IP address to Mikrotik router address list.
# Author: Erwin Bejsta, Control Technologies P/L
#
# Acknowledgements:
# Based on Federico Ciliberti's (https://github.com/ellocofray)
# mikrotik-perl-api (https://github.com/ellocofray/mikrotik-perl-api)
#
# Mikrotik API details: https://wiki.mikrotik.com/wiki/Manual:API
#
# Pre-requisites:
# - Mikrotik router (RouterOS) API enabled & user with write access
# - Mikrotik perl module Mtik.pm (https://github.com/ellocofray/mikrotik-perl-api)
#
# Functional Description
# Script input: ip address, address list name and timeout (optional)
# Step 1: The ip address is passed through a filter to determine if
#         - the ip has been seen multiple times [$filter_qty]
#         - the time between IP sightings is less than [$filter_expire]
#         if the above conditions are met proceed to step 2.
# Step 2: Establish if the IP is already present in the specified
#         Mikrotik address list. If note present go to Step 3
# Step 3: Add the IP to the specified address list in the Mikrotik
#         Add a syslog entry
#
###############################################################################
# Version History:
#
# V1.00 - 24 May 2019
# initial version deployed to block SASL login failures from mail.log
###############################################################################

use strict;
use Getopt::Std;
use Sys::Syslog qw(:DEFAULT setlogsock);

use vars qw($error_msg $debug);
use lib "/usr/share/mtik";              # the location Mtik.pm
use Mtik;

$Mtik::debug = 0;

###############################################################################
# Configuration parameters - Adjust to your environment!!!!!
my($mtik_host) = '192.168.1.1';   # <<------- !!!
my($mtik_username) = 'username';  # <<------- !!! (for Mikrotik)
my($mtik_password) = 'userpwd';   # <<------- !!!
my($default_timeout) = '7d 00:00:00';  # default address list timeout
my($filter_qty) = 2;			       # max number of failed logins before blocking
my($filter_expire) = 300;		     # max seconds between failures
###############################################################################
#
# Syslogging options
# NOTE: comment out the $syslog_socktype line if syslogging does not
# work on your system.
#
my($syslog_socktype) = 'unix'; # inet, unix, stream, console
my($syslog_facility)="mail";
my($syslog_options)="pid";
my($syslog_priority)="info";
###############################################################################

my($timeout);
my($block_ip);
my($list_name);

my($using_stdin) = 0;
my(%filter_ip);
my(%filter_time);


sub filter_ip
{
    my($block_ip) = @_;
    my($retval) = 0;            # don't block the ip
    # get current time
    my($now) = time();
    # do we have the ip in the filter
    if(exists $filter_ip{$block_ip}) {
        # get last filter time
        my($time_since_last) = $now - $filter_time{$block_ip};
	      # is the ip within expiry time?
        if ($time_since_last < $filter_expire) {
             $filter_ip{$block_ip}++;
             # has ip count neen reached?
             if ($filter_ip{$block_ip} > $filter_qty) {
	               $retval = 1;	# yes - the ip is now ready to be blocked
             }
         }
    } else {
        # add ip to filter table with count 1
        $filter_ip{$block_ip} = 1;
    }
    # update filter time
    $filter_time{$block_ip} = $now;
    #print ">>> $block_ip: $filter_ip{$block_ip}  $filter_time{$block_ip}\n";
    return $retval;
}

# delete expired filter entries
sub filter_expire
{
    my($expired_time) = time() - $filter_expire;
    # iterate through filter
    foreach my $ip(keys %filter_time) {
        my($ip_time) = $filter_time{$ip};
        # has the ip entry expired ?
        if ($ip_time < $expired_time) {
            delete $filter_ip{$ip};
            delete $filter_time{$ip};
	      }
    }
}

sub mtik_firewall_address_list_get_ips
{
    # get a list of all ips in the address list.
    my(%list_ips);
    my(@query) = '/ip/firewall/address-list/print' ;
    push(@query, '?list=' .  $list_name);
    #push(@query, 'address');
    my($retval,@results) = Mtik::talk(\@query);
    if ($Mtik::error_msg eq '')
    {
        foreach my $attrs (@results)
        {
            foreach my $attr (keys (%{$attrs}))
	    {
		my $val = ${$attrs}{$attr};
		if ($attr eq 'address')
		{
		    $list_ips{$val} = $list_name;
		    #push(@list_ips,$val);
		}
		if ($Mtik::debug > 5)
		{
		    print"$attr=$val\n";
		}
	    }
        }
    }
    # we return the array rather than setting a global, as we pretty much always
    # want to call this routine prior to doing anything with the address list, even if it
    # has already been called, in case someone else has changed the list
    # underneath us.
    return %list_ips;
}

sub mtik_firewall_address_list_ip_exists
{
    my($block_ip) = shift;
    # we need to load the address list every time we check, because other
    # people could be actively making changes
    my(%list_ips) = &mtik_firewall_address_list_get_ips();
    if ($Mtik::error_msg)
    {
        chomp($Mtik::error_msg);
        $Mtik::error_msg .= "\naddress list not loaded\n";
        return -1;
    }
    return(defined($list_ips{$block_ip}));
}

sub mtik_firewall_address_list_add
{
    my(%attrs) = %{(shift)};

    # first lets check to see if this IP already exists
    my($exists) = mtik_firewall_address_list_ip_exists($attrs{'address'});
    if ($exists != 0)
    {
        if ($exists > 0)
        {
            print "IP already on $list_name address list: $attrs{'address'}\n";
        }
        else
        {
            print "Unknow error: $Mtik::error_msg\n";
        }
        return 0;
    }

    # doesn't exist, so go ahead and add it
    my($retval,@results) = Mtik::mtik_cmd('/ip/firewall/address-list/add',\%attrs);
    if ($retval == 1)
    {
        # Mtik ID of the added item will be in $results[0]{'ret'}
        my($mtik_id) = $results[0]{'ret'};
        if ($Mtik::debug)
        {
            print "New Mtik ID: $mtik_id\n";
        }
        return $mtik_id;
    }
    else
    {
        # Error message will be in $Mtik::error_msg
        print "Unknown error: $Mtik::error_msg\n";
        return 0;
    }
}

sub block_ip {
    #print "Logging in to Mtik: $mtik_host\n";
    if (Mtik::login($mtik_host,$mtik_username,$mtik_password)) {
        # add a new IP to address list.
        #print "\nAdding IP $block_ip to address list $list_name\n";
        my(%attrs);
        $attrs{'list'} = $list_name;
        $attrs{'address'} = $block_ip;
        $attrs{'timeout'} = $timeout;
        if (my $mtik_id = &mtik_firewall_address_list_add(\%attrs)) {
            if ($Mtik::debug)
            {
                print "Added IP $block_ip to $list_name list with id: $mtik_id\n";
            }
            syslog $syslog_priority, "Mikrotik: IP [%s] added to address list %s",
                $block_ip, $list_name;
        }
        Mtik::logout;
    }
}

sub usage {
  print STDERR <<EOF;

Add IP address to Mikrotik address list.
command line usage: $0 -a ip-to-add -l address-list-name [-t timeout]
pipe usage: ip-to-add address-list-name [timeout]

if timeout is not supplied the default timeout will be used.
ip-to-add and address-list-name are mandatory.

examples:
$0 a=1.2.3.4 l=mylist t='1d 00:00:00'
echo "1.2.3.4 mylist 1d 00:00:00" | $0

EOF
  exit 1;
}

###############################################################################
###### main
###############################################################################

# open syslog
setlogsock $syslog_socktype;
openlog $0, $syslog_options, $syslog_facility;

my($option_str) = "a:l:t:";   # available options
my(%options);

# is the input attached to a terminal?
if (-t STDIN) {
    # yes - we expect a command line
    my(%options);
    my($option_str) = "a:l:t:";
    getopts($option_str,\%options);
    $block_ip =  $options{'a'};
    $list_name =  $options{'l'};
    $timeout = $options{'t'};
    goto START;
}

my($str);
my(@spl);
$using_stdin = 1;

READSTDIN:
# input is from another process or pipe
# we expect arguments in fixed order: block_ip list_name [timeout]
$str=<STDIN>;
if (!$str) {
    goto ENDPRG;
}
@spl = split(' ',$str);
$block_ip = $spl[0];
$list_name = $spl[1];
# check if timeout is like "3d 00:00:00" ( has space in argument)
if($spl[3]) {
    $timeout = $spl[2] . ' ' . $spl[3];
} else {
    $timeout = $spl[2];
}

START:

# if we are missing parameters show usage
if (!$block_ip || !$list_name) {
    usage();
}

# use default timeout is not supplied
if (!$timeout) {
    $timeout = $default_timeout;
}

# if the filter returns true we block the IP
if (filter_ip($block_ip)) {
    block_ip();
}
# delete expired filter entries
filter_expire();

# if using STDIN we could have multiple lines to process
if ($using_stdin) {
    goto READSTDIN;
}

ENDPRG:
exit 0;

###############################################################################
###### The End
###############################################################################

__END__
