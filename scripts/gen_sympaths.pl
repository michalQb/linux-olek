#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0-only
#
# The script generates a list of symbols per each AR thin archive and then
# collects them back during the final linking to obtain symbol filepaths.
# For local symbols, STT_FILE symbols are being used.
#

use strict;
use warnings;

my $symlist = {};
my $fh;

sub put_list
{
	my $name = $_[0];
	my $path = $_[1];
	my $type = $_[2];
	my $elem;
	my @arr;

	$elem = $symlist->{$name};

	if (!defined($elem)) {
		$arr[0] = $path;

		$symlist->{$name} = {
			'arr'	=> \@arr,
			'count'	=> 1,
		};

		$elem = $symlist->{$name};
	} else {
		$elem->{'arr'}->[$elem->{'count'}++] = $path;
	}

	if ($type =~ /^[[:lower:]]$/) {
		return;
	}

	if (!defined($elem->{'type'}) ||
	    ($elem->{'type'} eq "V" && !($type eq "V")) ||
	    ($elem->{'type'} eq "W" && !($type eq "V") && !($type eq "W"))) {
		$elem->{'type'} = $type;
		$elem->{'widx'} = $elem->{'count'} - 1;
	}
}

sub process_obj
{
	my $final = $_[1];
	my $start = 0;
	my $path;

	open(my $fh, "\"$ENV{NM}\" -ap \"$_[0]\" 2>/dev/null |")
		or die "Failed to execute \"$ENV{NM}\" -ap \"$_[0]\": $!";

	while (<$fh>) {
		my $type;
		my $name;

		($type, $name) = $_ =~ /^[0-9a-fA-F\s]+\s(.)\s(\S+)\n$/;

		if (!defined($type) || !defined($name)) {
			next;
		}

		if (!$start && $type eq "a") {
			$start = 1;
		}

		if (!$start || substr($name, 0, 3) eq ".LC") {
			next;
		}

		if ($type eq "a" && rindex($name, ".") > 0) {
			if ($final) {
				$path = $name;
			} else {
				print "F $name\n";
			}

			next;
		}

		if ($type eq "U" || $type eq "u") {
			next;
		}

		if ($final) {
			put_list($name, $path, $type);
		} else {
			print "$type $name\n";
		}
	}

	close($fh);
}

sub drop_list
{
	my $name = $_[0];
	my $path = $_[1];
	my $elem;

	$elem = $symlist->{$name};

	if (!defined($elem)) {
		return;
	}

	my ($index) = grep { $elem->{'arr'}->[$_] eq $path }
		      0 .. $elem->{'count'} - 1;

	if (defined($index)) {
		if ($elem->{'count'} == 1) {
			delete($symlist->{$name});
		} else {
			splice(@{$elem->{'arr'}}, $index, 1);
			$elem->{'count'}--;

			if (defined($elem->{'widx'}) &&
			    $elem->{'widx'} > $index) {
				$elem->{'widx'}--;
			}
		}
	}
}

sub get_list
{
	my $elem;

	$elem = $symlist->{$_[0]};

	if (!defined($elem)) {
		return undef;
	}

	if ($elem->{'count'} == 1) {
		return $elem->{'arr'}->[0];
	}

	if (!defined($elem->{'type'})) {
		return undef;
	}

	return $elem->{'arr'}->[$elem->{'widx'}];
}

sub gen_sym_file
{
	for my $i (1 .. $#ARGV) {
		my $file = $ARGV[$i];

		if ($file =~ /^.*\.a$/) {
			$file =~ s/.$/syms/;

			open $fh, "$file" or die "Failed to open $file: $!";
			print <$fh>;
			close $fh;
		} else {
			process_obj($file, 0);
		}
	}
}

if ($ARGV[0] eq "gen") {
	gen_sym_file();
	exit;
}

for my $i (1 .. $#ARGV) {
	my $file = $ARGV[$i];

	if ($file =~ /^.*\.a$/) {
		my $path;

		$file =~ s/.$/syms/;

		open $fh, "$file" or die "Failed to open $file: $!";

		while (<$fh>) {
			my $type;
			my $name;

			($type, $name) = $_ =~ /^(.) (.+)\n$/;

			if ($type eq "F") {
				$path = $name;
			} else {
				put_list($name, $path, $type);
			}
		}

		close $fh;
	} else {
		process_obj($file, 1);
	}
}

my @ksyms = ();
my $start = 0;
my $path;

open($fh, "\"$ENV{NM}\" -ap \"$ARGV[0]\" 2>/dev/null |")
	or die "Failed to execute \"$ENV{NM}\" -ap \"$ARGV[0]\": $!";

while (<$fh>) {
	my $vmlinux_lds = "$ENV{KBUILD_LDS}.S";
	my $address;
	my $type;
	my $name;
	my $file;

	($address, $type, $name) = $_ =~ /^([0-9a-fA-F]+) (.) (.+)\n$/;

	if (!defined($address) || !defined($type) || !defined($name)) {
		next;
	}

	if (!$start && $type eq "a") {
		$start = 1;
	}

	if (!$start || substr($name, 0, 3) eq ".LC") {
		next;
	}

	if ($type eq "a" && rindex($name, ".") > 0) {
		$path = $name;
		next;
	}

	if ($type =~ /^[[:lower:]]$/) {
		drop_list($name, $path);
		$file = $path;
	} else {
		$path = undef;
		$file = get_list($name);
	}

	if (!defined($file)) {
		if ($ARGV[0] =~ /^\.tmp_vmlinux.*$/) {
			$file = $vmlinux_lds;
		} else {
			$file = "$ARGV[0]";
			$file =~ s/.$/ko/;
		}
	}

	push(@ksyms, "$address $type $file:$name");
}

close($fh);

my $last = "";

for my $ksym (sort { substr($a, 19) cmp substr($b, 19) } @ksyms) {
	my $curr = substr($ksym, 19);

	die "Ambigous kallsym $curr may break kernel, aborting" if $curr eq $last;
	$last = $curr;
}

for my $ksym (sort { substr($a, 0, 18) . substr($a, rindex($a, ":") + 1) cmp
		     substr($b, 0, 18) . substr($b, rindex($b, ":") + 1) } @ksyms) {
	print "$ksym\n";
}
