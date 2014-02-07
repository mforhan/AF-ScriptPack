#!/usr/bin/perl

# snmpwalk -v1 -c public 192.168.1.2 1.3.6.1.2.1.4.22 | sed y/\./\ / | awk '{print $11}' | sort | uniq | grep ^2

# my $oid_IPtoMAC = 'iso.3.6.1.2.1.4.22.1.2.2147443544.';
# my $oid_IPtoMAC = 'iso.3.6.1.2.1.4.22.1.2.2147443400.'; 

#iso.3.6.1.2.1.3.1.1.2.2147443400.1.192.168.1.136 = Hex-STRING: 88 1F A1 21 AE 0A 
#iso.3.6.1.2.1.4.22.1.2.2147443400.192.168.1.136 = Hex-STRING: 88 1F A1 21 AE 0A 

sub check_oid($) {
        my $oid_IPtoMAC = shift;
	my $oid_base = ".1.3.6.1.4.1.2021.255.3.54.1.3.32.1.";
	my $oid_mac = 4;
	my $oid_snr = 26;

	my $IP_block = '192.168.1.';
	my $IP_range = 110;
	my %finalHash = ();
	my $response = 1;
	for($IP_range = 110;$IP_range <= 200;$IP_range++) {
	   $snmp_walk_opts = $oid_IPtoMAC.$IP_block.$IP_range;
	   # print $snmp_walk_opts."\n";
	   $ret = `/usr/bin/snmpwalk -v1 -c public 192.168.1.1 $snmp_walk_opts`;
	   ($key, $value) = split(/:/, $ret);
	   $value = substr($value, 0, -1);
	   $value =~ tr/ //ds;
	   $finalHash{$value}{'IP'} = $IP_block.$IP_range  if $value;
	   # print "[$value] [$IP_block$IP_range]\n" if $value;
	}

	for($i = 1;$i < 100;$i++) {
	  $snmp_walk_opts = $oid_base.$oid_mac.".".$i;
	  # print $snmp_walk_opts."\n";
	  $ret = `/usr/bin/snmpwalk -v1 -c public 192.168.1.1 $snmp_walk_opts`;

	  if($ret) {
	    ($key, $mac) = split(/:/, $ret);
	    $mac = substr($mac, 0, -1);
	    $mac =~ tr/ //ds;

	    $snmp_walk_opts = $oid_base.$oid_snr.".".$i;
	    # print $snmp_walk_opts."\n";
	    $ret = `/usr/bin/snmpwalk -v1 -c public 192.168.1.1 $snmp_walk_opts`;
	    ($key, $snr) = split(/:/, $ret);
	    # $snr = substr($snr, 0, -1);
	    # $snr =~ tr/ //ds;
	    $snr = int($snr);
	    $finalHash{$mac}{'SNR'} = $snr ;
	    # print "[$value]\n";
	  } else {
	    last;
	  }
	}

	# print "--------------------------------------------------\n";
	my $first = 1;
	my $count = 0;
	while( ($key, $value) = each %finalHash) {
	  # print "[$key] = [$value]\n";
	  if( $key && $finalHash{$key}{'IP'} && $finalHash{$key}{'SNR'} ) {
	    # print "[$key] = $finalHash{$key}{'IP'}\n";
	    # print "[$key] = $finalHash{$key}{'SNR'}\n";
	    $finalString .= "; " if !$first;
	    $first = 0 if $first;
	    $finalString .= $finalHash{$key}{'IP'}."=".$finalHash{$key}{'SNR'};
	    $count++;
	  }
	#for(keys %finalHash) {
	#  print "[$_] = ".$finalHash[$_]."\n";
	}
  # print "DEBUG: returning [$count] [$finalString]\n";
  return($count, $finalString);
}

my $oid_IPtoMAC = 'iso.3.6.1.2.1.4.22.1.2.2147443400.'; 

my ($finalCount,$string) = check_oid($oid_IPtoMAC);

# print "DEBUG: [$finalCount] [$string] from [$oid_IPtoMAC]\n";

if ($finalCount eq 0) {
  # print "changing oid...\n";
  $oid_IPtoMAC = 'iso.3.6.1.2.1.4.22.1.2.2147443544.';
  ($finalCount,$string) = check_oid($oid_IPtoMAC);
} 
print "$0 OK: $finalCount | addresses=$finalCount; $string\n";
