#!/usr/bin/perl
use strict;
use warnings;

use Text::CSV;

$| = 1;

my $csv = Text::CSV->new ( { binary => 1 } ) or die $!;
open my $fh, '<:encoding(utf8)', $ARGV[0] or die $!;

$csv->header($fh);

# print: IPaddr ORport

while ( my $row = $csv->getline($fh) ) {
    print "$row->[4] $row->[6]\n";
}

$csv->eof or $csv->error_diag();
close $fh;

exit 0;
