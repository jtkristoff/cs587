#!/usr/bin/perl -T
use strict;
use warnings;
$| = 1;

use Data::Dumper;
use DBD::Pg;
use Encode;
use Getopt::Std;
use Net::SSLeay;
use IO::Socket::SSL;
use Parallel::ForkManager;
use POSIX qw(strftime);
use Socket;
use utf8;

use constant DEFAULT_FORKS        => 40;
use constant DEFAULT_DPORT        => 443;
use constant DEFAULT_TIMEOUT      => 10;
use constant DEFAULT_TABLE        => 'x509cert';

use constant USAGE => "
$0
    [ -dDh ] [ -m max_forks ] [ -p dport ]
    [ -s saddr ] [ -t timeout ] probe_list

  -d                dump to stdout, disables database updates
  -D                enable debugging (noisy stdout)
  -h                help message
  -m max_forks      maximum forked processes, default is 40
  -s saddr          source IP address, default is discovered automatically
  -t timeout        process timeout in seconds, default is 10

  probe_list is a list of IPv4 addresses, one per line, to probe for an
  X.509 certificate.  Blank lines are ignored as are any comments.
  Comments follow the hash '#' character.  The default destination port
  is 443 unless the port is specified following the address separated by
  whitespace.
";

getopts( 'dDhm:s:t:', \my %opts );
die USAGE if $opts{h};

my $max_forks = $opts{m} || DEFAULT_FORKS;
my $saddr     = untaint_ipv4addr($opts{s}) || discover_saddr();
my $timeout   = $opts{t} || DEFAULT_TIMEOUT;

my $pm = new Parallel::ForkManager($max_forks);

while ( defined( my $line = <> ) ) {
    $pm->start and next;

    chomp $line;

    # skip blank lines or comments
    next if $line =~ m{ \A \s* (?: [#] [.]* )? \Z }xms;
    # remove leading spaces
    $line =~ s{ \A \s* }{}xms;
    # remove trailing spaces
    $line =~ s{ \s* \Z }{}xms;

    # capture IPv4 address and optional port
    my ( $dhost, $dport )
        = $line =~ m{ \A (\d{1,3} (?: [.] \d{1,3}){3}) \s* (\d{1,5})? \Z }xms;

    # give port a default value if none provided
    $dport ||= DEFAULT_DPORT;

    # additional sanity checks
    next if !$dhost;
    # convert dotted decimal IPv4 address to integer
    my @bytes = split /\./, $dhost;
    my $addr_as_int = unpack( 'N', pack('C4', @bytes) );
    # verify addr_as_interger is in range
    next if $addr_as_int < 0 || $addr_as_int > 4294967295;
    # verify port is in range
    next if $dport < 1 || $dport > 65535;

    # get cert from the target
    my $cert_href = ssl_probe( {
        dhost => $dhost,
        dport => $dport,
    } );

    # insert target cert detail to the db
    db_insert($cert_href);

    $pm->finish;
}

$pm->wait_all_children;

exit 0;

sub discover_saddr {
    my $sock = IO::Socket::SSL->new(
	Family   => AF_INET,    # XXX: we force IPv4
        PeerAddr => 'www.google.com',
        PeerPort => 443,
        Proto    => 'tcp',
        Timeout  => $timeout,
    );

    if ( !$sock ) {
        die "Unable to discover saddr ", IO::Socket::SSL::errstr();
    }

    my $saddr = $sock->sockhost;

    $sock->shutdown(0);
    $sock->close( { SSL_ctx_free => 1 } );

    return $saddr;
}

sub untaint_ipv4addr {
    my $addr = shift || return;

    ($addr) = $addr =~ m{ \A ( \d{1,3} (?: [.] \d{1,3} ){3} ) \Z }xms;

    return $addr;
}

sub ssl_probe {
    my $probe = shift || return;
    my $dhost = $probe->{dhost};
    my $dport = $probe->{dport};

    my $sock = IO::Socket::SSL->new(
        Proto           => 'tcp',
        LocalAddr       => $saddr,
        PeerAddr        => $dhost,
        PeerPort        => $dport,
        Timeout         => $timeout,
	SSL_verify_mode => SSL_VERIFY_NONE,
    );

    # an open port doesn't mean it is an SSL/TLS service
    if (!$sock) {
        warn "$dhost:$dport ", IO::Socket::SSL::errstr() if $opts{D};
        return;
    }

    sleep 5;
    my $sport = $sock->sockport();

    my $cert  = $sock->peer_certificate();
    # make sure there is a cert we can parse
    if (!$cert) {
        warn "$dhost:$dport ", IO::Socket::SSL::errstr() if $opts{D};
        $sock->shutdown(0);
        $sock->close( { SSL_ctx_free => 1 } );
        return;
    }

    # these probe keys corrleate to field names for the db insert
    $probe->{hostname}  = $dhost;
    $probe->{addr}      = $sock->peerhost;
    $probe->{port}      = $dport;
    $probe->{pem}       = x509_pem( \$cert );
    $probe->{serial}    = x509_serial( \$cert );
    $probe->{version}   = x509_version( \$cert );
    $probe->{md5}       = x509_md5( \$cert );
    $probe->{sha1}      = x509_sha1( \$cert );
    $probe->{issuer}    = x509_issuer( \$cert );
    $probe->{issuer_CN} = x509_issuer_CN( \$cert );
    $probe->{issuer_C}  = x509_issuer_C( \$cert );
    $probe->{issuer_O}  = x509_issuer_O( \$cert );
    $probe->{subject}   = x509_subject( \$cert );
    $probe->{CN}        = x509_CN( \$cert );
    $probe->{altNames}  = x509_altNames( \$cert );
    $probe->{C}         = x509_C( \$cert );
    $probe->{O}         = x509_O( \$cert );
    $probe->{email}     = x509_email( \$cert );
    $probe->{notAfter}  = x509_notAfter( \$cert );
    $probe->{notBefore} = x509_notBefore( \$cert );
    $probe->{sigAlgo}   = x509_sigAlgo( \$cert );
    $probe->{datasrc}   = "active probe from $saddr:$sport";

    $sock->shutdown(0);
    $sock->close( { SSL_ctx_free => 1 } );

    if ( $opts{d} ) { print Dumper($probe); }

    return $probe;
}

sub db_insert {
    my $x509cert = shift || return;
    my $table = DEFAULT_TABLE;
    my @cert_attributes = qw(
      hostname
      port
      addr
      pem
      serial
      version
      md5
      sha1
      issuer
      issuer_CN
      issuer_C
      issuer_O
      subject
      CN
      altNames
      C
      O
      email
      notAfter
      notBefore
      sigAlgo
      datasrc
    );
    my @cert_values;

    for my $attribute (@cert_attributes) {
        push @cert_values, encode( 'UTF-8', $x509cert->{$attribute} ) || undef;
    }

    # enjoy the array manipulation hackery that minimizes typos
    my $sql_cmd =
        "INSERT INTO $table ("
      . join( ',', @cert_attributes )
      . ') VALUES('
      . '?,' x ( scalar @cert_attributes - 1 ) . '?' . ')';

    if ( $opts{d} ) {
        print Dumper($sql_cmd);
        print Dumper(@cert_values);
        return;
    }

    # continue only if we're doing database inserts

    my $dbh_ref = db_connect();
    my $sth     = $dbh_ref->prepare($sql_cmd)
      or die 'db preparation error: ' . DBI->errstr;
    $sth->execute(@cert_values)
      or die 'db execution error: ' . DBI->errstr;

    $sth->finish
      or die 'db finish error: ' . DBI->errstr;

    db_disconnect($dbh_ref);

    return;
}

sub db_connect {
    return if $opts{d};

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
    return if $opts{d};

    my $dbh_ref = shift;

    $dbh_ref->disconnect
      or die 'db disconnect error: ' . DBI->errstr;

    return;
}

sub x509_pem {
    my $cert_ref = shift;
    my $pem      = Net::SSLeay::PEM_get_string_X509($$cert_ref);
    chomp $pem;
    return $pem;
}

sub x509_serial {
    my $cert_ref = shift;
    return Net::SSLeay::P_ASN1_INTEGER_get_hex(
        Net::SSLeay::X509_get_serialNumber($$cert_ref) );
}

sub x509_version {
    my $cert_ref = shift;
    my $version  = Net::SSLeay::X509_get_version($$cert_ref);

    # Net::SSLeay structure starts counting at zero
    if ($version) {
        $version++;
    }

    return $version;
}

sub x509_md5 {
    my $cert_ref = shift;
    return Net::SSLeay::X509_get_fingerprint( $$cert_ref, 'md5' );
}

sub x509_sha1 {
    my $cert_ref = shift;
    return Net::SSLeay::X509_get_fingerprint( $$cert_ref, 'sha1' );
}

sub x509_issuer {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_oneline(
        Net::SSLeay::X509_get_issuer_name($$cert_ref) );
}

sub x509_issuer_CN {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_get_text_by_NID(
        Net::SSLeay::X509_get_issuer_name($$cert_ref),
        &Net::SSLeay::NID_commonName );
}

sub x509_issuer_C {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_get_text_by_NID(
        Net::SSLeay::X509_get_issuer_name($$cert_ref),
        &Net::SSLeay::NID_countryName );
}

sub x509_issuer_O {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_get_text_by_NID(
        Net::SSLeay::X509_get_issuer_name($$cert_ref),
        &Net::SSLeay::NID_organizationName );
}

sub x509_subject {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_oneline(
        Net::SSLeay::X509_get_subject_name($$cert_ref) );
}

sub x509_CN {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_get_text_by_NID(
        Net::SSLeay::X509_get_subject_name($$cert_ref),
        &Net::SSLeay::NID_commonName );
}

sub x509_altNames {
    my $cert_ref = shift;
    return Net::SSLeay::X509_get_subjectAltNames($$cert_ref);
}

sub x509_C {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_get_text_by_NID(
        Net::SSLeay::X509_get_subject_name($$cert_ref),
        &Net::SSLeay::NID_countryName );
}

sub x509_O {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_get_text_by_NID(
        Net::SSLeay::X509_get_subject_name($$cert_ref),
        &Net::SSLeay::NID_organizationName );
}

sub x509_email {
    my $cert_ref = shift;

    return Net::SSLeay::X509_NAME_get_text_by_NID(
        Net::SSLeay::X509_get_subject_name($$cert_ref),
        &Net::SSLeay::NID_pkcs9_emailAddress
    );
}

sub x509_notAfter {
    my $cert_ref = shift;

    return Net::SSLeay::P_ASN1_TIME_get_isotime(
        Net::SSLeay::X509_get_notAfter($$cert_ref) );
}

sub x509_notBefore {
    my $cert_ref = shift;

    return Net::SSLeay::P_ASN1_TIME_get_isotime(
        Net::SSLeay::X509_get_notBefore($$cert_ref) );
}

sub x509_sigAlgo {
    my $cert_ref = shift;

    return Net::SSLeay::OBJ_obj2txt(
        Net::SSLeay::P_X509_get_signature_alg($$cert_ref) );
}
