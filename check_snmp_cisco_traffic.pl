#!/usr/bin/perl -w
### check_cisco_traffic_usage.pl
# Check Traffic Usage of an Interface on a Cisco Device
# 
# This is a bit tricky, because cisco's snmp counter are independent from the cli output.
# The snmp counters can't be reset at runtime, they online reset themself at reboot.
# So in addition to the snmp values we get, we need to calculate....
#
# We save the last check results/sums in a text file so make sure you set "statfile" below.
# 
# This plugin currently only uses HC/64bit counter, because 32bit begin from zero too often.
# You also have to find out the interface number yourself, i don't, yet, want the script to
# search for it every runtime. Just snmpwalk your device like this:
#
# $ snmpwalk -v2c -c community-string HOST 1.3.6.1.2.1.31.1.1.1.1
# IF-MIB::ifName.1 = STRING: Fa0
#          This -^- is the interface-number
#
# Version 0.1, Copyright (c) 2008 by Michael Boehm <dudleyperkins_AT_gmail.com>
#
# Version 0.1.1, Copyright (c) 2011 by vaclav.ovsik_AT_gmail.com
#   * rewrite from shell to Perl
#
# TODO: -testing
#	-maybe accepting Interface descriptions as argument
#	-maybe include check for 32bit counter
###

### License Information:
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# you should have received a copy of the GNU General Public License
# along with this program (or with Nagios);  if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA
###

use strict;
use bignum;
use Net::SNMP;
use Getopt::Long qw(:config no_ignore_case);

# SNMP OIDs
my $oidIfDescr     	= '1.3.6.1.2.1.2.2.1.2';
my $oidIfSpeed     	= '1.3.6.1.2.1.2.2.1.5';
my $oidIfOperStatus 	= '1.3.6.1.2.1.2.2.1.8';
my $oidIfName		= '1.3.6.1.2.1.31.1.1.1.1';
my $oidIfInOctets  	= '1.3.6.1.2.1.31.1.1.1.6';
my $oidIfOutOctets 	= '1.3.6.1.2.1.31.1.1.1.10';
my $oidIfAlias		= '1.3.6.1.2.1.31.1.1.1.18';

my $snmp_port    = 161;
my $snmp_version = 2;

my $statdir = "/var/tmp";

my %STATUS_CODE = (
    'UNKNOWN'	=> 3,
    'OK'	=> 0,
    'WARNING'	=> 1,
    'CRITICAL'	=> 2,
);

my $warn = '85%';
my $crit = '98%';

# Print results and exit script
sub stop
{
    my ($result, $exitcode) = @_;
    print "$result\n";
    exit($STATUS_CODE{$exitcode});
};

sub usage
{
    my ($exitcode) = @_;
    print <<EOF;
Check Traffic Usage of an Interface on a Cisco Device
Original shell code Copyright (c) 2008 by Michael Boehm <dudleyperkins_AT_gmail.com>
Rewriten into Perl by vaclav.ovsik_AT_gmail.com
Version 0.1.1

usage: check_snmp_cisco_traffic.pl <options>

options:

    -H, --host STRING or IPADDRESS
        Check interface on the indicated host.
    -C, --community STRING 
        SNMP Community (version 1 doesnt work!).
    -i, --interface INTEGER
        Interface Number
	Is easily found out, snmpwalk your device like this:
		--> snmpwalk -v2c -c community-string HOST 1.3.6.1.2.1.31.1.1.1.1
		--> IF-MIB::ifName.1 = STRING: Fa0
			     This -^- is the interface-number
    -w, --warning <warn-level>
        bandwidth usage necessary to result in warning status (default: $warn)
	 - number without suffix represents absolute value B/s,
	 - number with % suffix represents per cent of max interface speed,
	 - 1B/s = 1Bps = 8b/s = 8bps
	 - 1000B/s = 1kB/s = 8kbps...
	 - 1024Bps = 1KiB/s
	 - dtto 1MiB/s, 1GiB/s...
    -c, --critical <crit-level>
        bandwidth usage necessary to result in critical status (default: $crit)
	see --warning

EOF
    exit($exitcode) if defined $exitcode;
}

sub status_filename
{
    my ($host, $if_index) = @_;
    return "$statdir/check_snmp_cisco_traffic_${host}_${if_index}.txt";
}

sub write_status
{
    my ($host, $if_index, $time, $if_name, $if_in, $if_out) = @_;

    open(my $fh, '>', status_filename($host, $if_index))
	    || stop(qq|CRITICAL: can't write status file: $!|, 'CRITICAL');
    print $fh "$if_in $if_out $time $if_name\n";
    close($fh);
}

sub read_status
{
    my ($host, $if_index) = @_;

    open(my $fh, '<', status_filename($host, $if_index))
	    || stop(qq|CRITICAL: can't read status file: $!|, 'CRITICAL');
    $_ = <$fh>;
    close($fh);
    chomp;
    my ($if_in, $if_out, $time, $if_name) = split(m/\s+/, $_, 4);
    return ($time, $if_name, $if_in, $if_out);
}


my %mult = (
	''	=> 1,
	'k'	=> 10 ** 3,
	'M'	=> 10 ** 6,
	'G'	=> 10 ** 9,
	'Ki'    => 2 ** 10,
	'Mi'    => 2 ** 20,
	'Gi'    => 2 ** 30,
    );

sub handle_speed_level
{
    my ($level, $if_speed) = @_;
    $level =~ m/^(\d+(?:\.\d*)?)\s*(.*)$/
	    || die qq|Invalid speed limit "$level"\n|;
    my $units = $2;
    my $num = $1;
    return $if_speed * $num / 100 if $units eq '%';
    return $num if $units eq '';
    $units =~ m{^([kMG]|[KMG]i|)([bB])[/p]s$}
	    || die qq|Invalid speed limit units "$level"\n|;
    my $mult = $1;
    my $bitbyte = $2;
    $num /= 8 if $bitbyte eq 'b';
    exists $mult{$mult} || die qq|Unknown multiplier "$mult"!\n|;
    $num *= $mult{$mult};
    return $num;
}

my @units = qw( B/s KiB/s MiB/s GiB/s );

sub rate_to_human
{
    my ($num) = @_;
    for(my $i = 0; $i < @units; $i++, $num /= 1024)
    {
	return sprintf("%.2f %s", $num, $units[$i])
		if $num < 1024 || $i == $#units;
    }
    die;
}

MAIN:	{

    my ($help, $host, $if_index, $community);
    usage(1) unless GetOptions(
	    "help"          => \$help,
	    "H|hostname=s"  => \$host,
	    "i|interface=s" => \$if_index,
	    "C|community=s" => \$community,
	    "w|warning=s"   => \$warn,
	    "c|critical=s"  => \$crit,
	);
    usage(0) if $help;

    my ($session, $error);
    if ( $snmp_version == 1 || $snmp_version == 2 )
    {
	( $session, $error ) = Net::SNMP->session(
		-hostname  => $host,
		-community => $community,
		-port      => $snmp_port,
		-version   => $snmp_version,
	);
	defined($session) || stop("UNKNOWN: $error", "UNKNOWN");
    }
    elsif ( $snmp_version == 3 )
    {
	stop("UNKNOWN: No support for SNMP v3 yet\n", 'UNKNOWN');
    }
    else {
	stop("UNKNOWN: Unknown SNMP v$snmp_version\n", 'UNKNOWN');
    };

    my @snmpoids = map { $_ . "." . $if_index } (
	    $oidIfSpeed,
#	    $oidIfOperStatus,
	    $oidIfName,
	    $oidIfAlias,
	    $oidIfInOctets,
	    $oidIfOutOctets
	);

    my $response = $session->get_request(@snmpoids);
    unless ( $response )
    {
	my $answer = $session->error();
	$session->close();
	stop("WARNING: SNMP error: $answer\n", "WARNING");
    }

    my $if_speed  = $response->{"$oidIfSpeed.$if_index"} / 8;
    $warn = handle_speed_level($warn, $if_speed);
    $crit = handle_speed_level($crit, $if_speed);

#    my $if_status = $response->{"$oidIfOperStatus.$if_index"};
    my $if_name   = $response->{"$oidIfName.$if_index"};
    my $if_alias  = $response->{"$oidIfAlias.$if_index"};
    my $if_in     = $response->{"$oidIfInOctets.$if_index"};
    my $if_out    = $response->{"$oidIfOutOctets.$if_index"};

    $session->close();

    my $now = time();

    if ( ! -f status_filename($host, $if_index) )
    {
	write_status($host, $if_index, $now, $if_name, $if_in, $if_out);
	stop("UNKNOWN: values stored, wait for next run please\n", 'UNKNOWN');
    }

    my ($time_last, $if_name_last, $if_in_last, $if_out_last) = read_status($host, $if_index);

    write_status($host, $if_index, $now, $if_name_last, $if_in, $if_out);

    stop("CRITICAL: interface name changed! $if_name (was $if_name_last)", 'CRITICAL')
	    if $if_name ne $if_name_last;

    my $period = $now - $time_last;

    stop("UNKNOWN: zero time interval running script too fast", 'UNKNOWN')
	    if $period == 0;

    my $diff_in;
    if ( $if_in >= $if_in_last )
    {
	$diff_in = $if_in - $if_in_last;
    }
    else
    {
	# this counter cannot be reset, unless the system was restarted
	# so no calculation here - we assume the current value IS the diff
	$diff_in = $if_in;
    }
    my $rate_in = $diff_in / $period;

    my $diff_out;
    if ( $if_out >= $if_out_last )
    {
	$diff_out = $if_out - $if_out_last;
    }
    else
    {
	# this counter cannot be reset, unless the system was restarted
	# so no calculation here - we assume the current value IS the diff
	$diff_out = $if_out;
    }
    my $rate_out = $diff_out / $period;

    my $hrate_in = rate_to_human($rate_in);
    my $hrate_out = rate_to_human($rate_out);
    my $info = " - $if_name ($if_alias) In: $hrate_in, Out: $hrate_out"
		."|In=$rate_in;$warn;$crit;$if_speed; Out=$rate_out;$warn;$crit;$if_speed;";

    stop("Traffic CRITICAL$info\n", 'CRITICAL') if $rate_in >= $crit || $rate_out >= $crit;
    stop("Traffic WARNING$info\n", 'WARNING') if $rate_in >= $warn || $rate_out >= $warn;
    stop("Traffic OK$info\n", 'OK');
};
