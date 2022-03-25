#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;

my $default_name = "wg0";
my $default_dns = "185.228.168.10, 185.228.169.11"; # https://cleanbrowsing.org/filters

sub wireguardInstalled {
	return system("wg help > /dev/null 2>&1") == 0;
}

sub postCommands {
	my $from_iface = shift;
	my $to_iface = shift;
	"PostUp = iptables -A FORWARD -i $from_iface -j ACCEPT; iptables -A FORWARD -o $from_iface -j ACCEPT; iptables -t nat -A POSTROUTING -o $to_iface -j MASQUERADE\n".
	"PostDown = iptables -D FORWARD -i $from_iface -j ACCEPT; iptables -D FORWARD -o $from_iface -j ACCEPT; iptables -t nat -D POSTROUTING -o $to_iface -j MASQUERADE\n"
	;
}

sub getName {
	shift =~ /(\w+)\.conf$/;
	$1;
}

sub getIPv4 {
	my $phys_iface = shift // getFirstIface();
	# Get the server WAN IPv4 address
	`ip -o -4 addr list $phys_iface` =~ /([1-9]\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ or die $!;
	$1;
}

sub getIPv4Mult {
	 return ( shift =~ /([1-9]\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g );
}

sub backupFile {
	system("cp $_[0] $_[0]_\$(date +%Y-%m-%d_%H%M%S).bak") == 0
		or die "Unable to create backup of '$_[0]'!\n".$!;
}

sub getIPv4ListofMult {
	my @addr_list;
	foreach my $mult_str ( @_ ) {
		@addr_list = ( @addr_list, getIPv4Mult ($mult_str) );
	}
	return @addr_list;
}

sub getFirstIface {
	`ip addr` =~ /^.: (\w+): .+ state UP /m or die $!;
	$1;
}

sub readConf {
	wireguardInstalled() or die $!;
	my $conf_file_path = shift or die $!;
	
	# Open and parse the server conf file
	open CONF_HANDLE, $conf_file_path or die $!;
	my $conf_file = do {local $/; <CONF_HANDLE>};
	close CONF_HANDLE;
	
	my %output;

	# Read the Address
	$conf_file =~ /Address\s*=\s*(\S+)/ or die $!;
	$output{Address} = $1;

	# Read the private key
	$conf_file =~ /PrivateKey\s*=\s*(\S+)/ or die $!;
	$output{PrivateKey} = $1;

	# Derive the public key
	$output{PublicKey} = `echo "$output{PrivateKey}" | wg pubkey` or die $!;
	chomp $output{PublicKey};

	# Read the port
	$conf_file =~ /ListenPort\s*=\s*(\d+)/
	 and $output{ListenPort} = $1;
	
	# Get the first part of the name of the conf file
	$output{name} = getName( $conf_file_path );
	
	# Get DNS servers
	if ($conf_file =~ /DNS\s*=\s*(.+)$/m) {
		#my $dns_str = $1;
		my @dns_list = getIPv4Mult ($1);
		$output{DNS} = [ (@dns_list) ];
	}
	
	# Get a list of all the IPv4 address in the conf file
	my @address_list = getIPv4ListofMult($conf_file =~ /^AllowedIPs.*$/mg);
	$output{IPv4List} = [ ($output{Address}, @address_list) ];

	# Derive the next address
	my $last_address_str = $output{IPv4List}[-1]; 
	$last_address_str =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})/ or die $!;
	$output{IPv4Next} = $1.($2+1);

	return %output;
}


sub odd {
	((scalar @_) % 2) != 0
}


my %tool;

$tool{init} = sub {
	wireguardInstalled() or die $!;

	die "Odd number of arguments" if (odd @_);
	my %input = (
		conf				=> "/etc/wireguard/$default_name.conf",
		Address			=> "10.0.0.1",
		iface				=> getFirstIface(),
		ListenPort	=> "50000",
		DNS					=> $default_dns,
		@_
	);
	$input{name} = getName( $input{conf} );
	
	# If the file already exists, create a backup
	-e $input{conf} and (backupFile($input{conf}));

	# Write or overwrite the conf file
	open CONF_HANDLE, ">$input{conf}" or die $!;
	
	print CONF_HANDLE
		"# $input{name}\n".
		"[Interface]\n".
		"PrivateKey = ".`wg genkey`.
		"Address = $input{Address}\n".
		"ListenPort = $input{ListenPort}\n".
		"DNS = $input{DNS}\n".
		"\n".
		postCommands ( '%i', $input{iface}  )
	;
	close CONF_HANDLE;
	
	return %input;
};


$tool{enable} = sub {
	for my $name ( @_ ) {
		system('systemctl enable wg-quick@'.$name) == 0
			and system('systemctl start wg-quick@'.$name) == 0
			or die "Error enabling and starting: $name\n$!";
	}
};


$tool{disable} = sub {
	for my $name ( @_ ) {
		system('systemctl stop wg-quick@'.$name) == 0
			and system('systemctl disable wg-quick@'.$name) == 0
			or die "Error stopping and disabling: $name\n$!";
	}
};


$tool{status} = sub {
	my $error_state = 0;
	for my $name ( @_ ) {
		`systemctl status wg-quick\@$name` =~ /Active:\W+active\W+(exited)/
			and print "$name:UP\n"
			or do {
				print "$name:DOWN\n$!";
				$error_state++;
			};
	}
	exit 1 if ($error_state);
};


$tool{bounce} = sub {
	my $name = shift;
	print `wg-quick down $name`;
	print `wg-quick up $name`;
	die "Error bouncing: $name\n$!" if ($?);
};


$tool{append} = sub {
	wireguardInstalled() or die $!;
	
	my $default_comment = "Added: ".`date`;
	chomp $default_comment;
	
	die "Odd number of arguments" if (odd @_);
	my %input = (
		conf				=> "/etc/wireguard/$default_name.conf",
		comment			=> $default_comment,
		iface				=> getFirstIface(),
		DNS					=> $default_dns,
		AllowedIPs	=> "0.0.0.0/0, ::/0",
		@_
	);
	
	# name from file path
	$input{name} = getName $input{conf};
	
	# Read this node's conf file
	my %conf = readConf $input{conf};
	
	# Get this nodes's physical IPv4
	my $thisIPv4 = getIPv4 $input{iface};
	
	# Generate a private key for the peer entrance-node
	my $peer_private_key = `wg genkey`;
	# Generate a public key for the peer entrance-node
	my $peer_public_key = `echo "$peer_private_key" | wg pubkey`;
	
	# Virtual address for the peer
	my $peer_address = $input{Address} // $conf{IPv4Next};
	
	# try to backup this node's conf file
	backupFile($input{conf});	# Output a new entrance-node configuration file

	# Append to this node's conf file
	open CONF_HANDLE, '>>', $input{conf} or die "Unable to append to $input{conf}!\n".$!;
	print CONF_HANDLE
		"\n" .
		"[Peer]\n" .
		"# $input{comment}\n" .
		"PublicKey = $peer_public_key" .
		"AllowedIPs = $peer_address/32\n";
	close CONF_HANDLE;
	
	# Print the peer conf file
	print
		"[Interface]\n" .
		"PrivateKey = $peer_private_key" .
		"Address = $peer_address\n" .
		"DNS = $input{DNS}\n" .
		( defined($input{iface_peer}) ? "\n".postCommands( $input{iface_peer}, '%i' ) : "" ).
		"\n" .
		"[Peer]\n" .
		"PublicKey = $conf{PublicKey}\n" .
		"Endpoint = $thisIPv4:$conf{ListenPort}\n" .
		"AllowedIPs = $input{AllowedIPs}\n";
	
};


$tool{info} = sub {
	die "Odd number of arguments" if (odd @_);
	my %input = (
		conf	=> "/etc/wireguard/$default_name.conf",
		iface	=> getFirstIface(),
		@_
	);
	my $conf = { readConf( $input{conf} ) };
	my $thisIp = getIPv4( $input{iface} );

	print
		"My IPv4 on $input{iface}: ".$thisIp."\n".
		"Conf File: ".Dumper($conf);
};


# execute the tool based on args
my ($command, @args) = (@ARGV);
$tool{$command} (@args);


