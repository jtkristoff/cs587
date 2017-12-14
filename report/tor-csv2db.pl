#!/usr/bin/perl
use strict;
use warnings;

use DBD::Pg;
use Data::Dumper;
use Text::CSV;

use constant TABLE_NAME => 'tornode';

$| = 1;

my @column_names = qw(
    rname
    cc
    bandwidth
    uptime
    ipaddr
    hostname
    orport
    dirport
    auth
    exit
    fast
    guard
    named
    stable
    running
    valid
    v2dir
    platform
    hibernating
    badexit
    firstseen
    asname
    asn
    consensus
    address
);

my $csv = Text::CSV->new ( { binary => 1 } ) or die $!;
open my $fh, '<:encoding(utf8)', $ARGV[0] or die $!;

$csv->header($fh);
my $dbh_ref = db_connect();

while ( my $row = $csv->getline($fh) ) {

    # transform any value eq 'None' to an integer zero
    my @values = map { $_ eq 'None' ? 0 : $_ } @$row;

    # enjoy the array manipulation hackery that minimizes typos
    my $sql_cmd =
        'INSERT INTO ' . TABLE_NAME . ' ('
      . join( ',', @column_names )
      . ') VALUES('
      . '?,' x ( scalar @column_names - 1 ) . '?' . ')';

    my $sth     = $dbh_ref->prepare($sql_cmd)
      or die 'db preparation error: ' . DBI->errstr;
    $sth->execute(@values)
      or die 'db execution error: ' . DBI->errstr;
    $sth->finish
      or die 'db finish error: ' . DBI->errstr;
}

db_disconnect($dbh_ref);

$csv->eof or $csv->error_diag();
close $fh;

exit 0;

sub db_connect {
    my ($arg_ref) = @_;
    my $db_type = $arg_ref->{type} || 'Pg';
    my $db_host = $arg_ref->{host} || 'localhost';
    my $db_port = $arg_ref->{port} || 5432;
    my $db_user = $arg_ref->{user} || 'jtk';
    my $db_pass = $arg_ref->{pass} || '##PASSWORD##';
    my $db_name = $arg_ref->{db}   || 'cs587';
    my $db_dsn = "DBI:$db_type:dbname=$db_name;host=$db_host;port=$db_port";

    my $dbh = DBI->connect( $db_dsn, $db_user, $db_pass )
      or die 'db_connect error: ' . DBI->errstr;

    return $dbh;
}

sub db_disconnect {
    my $dbh_ref = shift;

    $dbh_ref->disconnect
      or die 'db disconnect error: ' . DBI->errstr;

    return;
}
