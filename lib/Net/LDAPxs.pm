#
# Copyright (c) 2008-2009 Pan Yu (xiaocong@vip.163.com). 
# All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#

package Net::LDAPxs;

use strict;

use Exporter;
use DynaLoader;
use vars qw($VERSION);
use vars qw($DEFAULT_LDAP_VERSION $DEFAULT_LDAP_PORT $DEFAULT_LDAP_SCHEME);

$VERSION = '0.02';

our @ISA = qw(Exporter DynaLoader);

our @EXPORT = ( );
our @EXPORT_OK = qw(
	new bind unbind search add abandon compare
);

bootstrap Net::LDAPxs;

$DEFAULT_LDAP_VERSION	= 3; 
$DEFAULT_LDAP_PORT		= 389; 
$DEFAULT_LDAP_SCHEME	= 'ldap'; 

my $error = {
		'die'	=> sub { require Carp; Carp::croak(@_); },
		'warn'	=> sub { require Carp; Carp::carp(@_); }
};

sub _error {
	my $error_code = shift;
	my $error_msg = shift;

	$error->{$error_code}($error_msg);
}

sub _check_options {
	my $arg_ref = shift;

	if (grep { /^-/ } keys %$arg_ref) {
		_error('die', "Leading - for options is NOT supported");
	}
	$arg_ref->{'port'} = $arg_ref->{'port'} || $DEFAULT_LDAP_PORT;
	$arg_ref->{'version'} = $arg_ref->{'version'} || $DEFAULT_LDAP_VERSION;
	$arg_ref->{'scheme'} = $arg_ref->{'scheme'} || $DEFAULT_LDAP_SCHEME;
}

sub new {
	my $class = shift;
	my $host = shift;
	my $arg_ref = { @_ };

	_check_options($arg_ref);

	my $port = $arg_ref->{'port'};
	my $version = $arg_ref->{'version'};
	my $scheme = $arg_ref->{'scheme'};
	$arg_ref->{'host'} = $host;

	return _new($class, $arg_ref);
}

sub bind {
	my $self = shift;
	my $binddn = shift;
	my $arg_ref = { @_ };

	$self->{binddn} = $binddn;
	$self->{bindpasswd} = $arg_ref->{password};
	my $rc = $self->_bind();

	if (ref($rc)) {
		$self->_set_err($$rc);
		return;
	}
}

sub unbind {
	my $self = shift;

	$self->_unbind();
}

my %scope = qw( base 0 one 1 sub 2 children 3 );

sub search {
	my $self = shift;
	my $arg_ref = { @_ };

	require Net::LDAPxs::Search;
	$self->{base} = $arg_ref->{base};
	$self->{filter} = $arg_ref->{filter};

	if (exists $arg_ref->{scope}) {
		my $scope = lc $arg_ref->{scope};
		$self->{scope} = (exists $scope{$scope}) ? $scope{$scope} : 2;
	}else{
		$arg_ref->{scope} = 2;
	}
	$self->{sizelimit} = $arg_ref->{sizelimit} || 0;
	$self->{attrs} = $arg_ref->{attrs};
	$self->_search();
}

sub add {
	my $self = shift;
	my $dn = shift;
	my $arg_ref = { @_ };

	if (exists $arg_ref->{attrs}) {
		$self->_add($dn, $arg_ref->{attrs});
	}else{
		_error('die', "Option 'attrs' is required when using 'add' function");
	}
}

sub compare {
	my $self = shift;
	my $dn = shift;
	my $arg_ref = { @_ };

	my $rc = $self->_compare($dn, $arg_ref->{attr}, $arg_ref->{value});
	if (ref($rc)) {
		$self->_set_err($$rc);
		return;
	}
}

sub _set_err {
	my $self = shift;
	$self->{err} = shift;
}

sub errstr {
	my $self = shift;
	$self->{err};
}

sub abandon {

}

1;

__END__

=head1 NAME

Net::LDAPxs - XS version of Net::LDAP

=head1 SYNOPSIS

  use Net::LDAPxs;

  $ldap = Net::LDAPxs->new('www.qosoft.com');

  $ldap->bind('cn=Manager,dc=shallot,dc=com', password => 'secret');

  $msg = $ldap->search( base   => 'ou=language,dc=shallot,dc=com',
                        filter => '(|(cn=aperture)(cn=shutter_speed))'
                      );

  @entries = $msg->entries();

  foreach my $entry (@entries) {
      foreach my $attr ($entry->attributes()) {
          foreach my $val ($entry->get_value($attr)) {
              print "$attr, $val\n";
          }
      }
  }

  $ldap->unbind;

=head1 DESCRIPTION

Net::LDAPxs is using XS code to glue LDAP C API Perl code. The purpose of 
developing this module is to thoroughly improve the performance of Net::LDAP. 
According to the simple test using L<Devel::NYTProf>, it can enhance the 
performance by nearly 30 times.
In order to benefit the migration from Net::LDAP to Net::LDAPxs, functions and 
user interfaces of Net::LDAPxs keep the same as Net::LDAP, which means people 
who migrate from Net::LDAP to Net::LDAPxs are able to leave their code 
unchanged excepting altering the module name. 

=head1 CONSTRUCTOR

=item new ( HOST, OPTIONS )

HOST can be a host name or an IP address without path information.

=over 4

=item port => N

Port connect to the LDAP server. (Default: 389)

=item scheme => 'ldap' | 'ldaps' | 'ldapi' (Default: ldap)

B<Example>

  $ldap = Net::LDAPxs->new('www.qosoft.com',
                           port    => '389',
                           scheme  => 'ldap',
                           version => 3
                          );

=head1 METHODS

Currently, not all methods of Net::LDAP are supported by Net::LDAPxs.
Here is a list of implemented methods.

=item bind ( DN, OPTIONS )

B<Example>

  $ldap->bind('cn=Manager,dc=shallot,dc=com', password => 'secret');

=item unbind ( )

B<Example>

  $ldap->unbind;

=item search ( ID, OPTIONS )

=over 4

=item base => ( DN )

A base option is a DN which is the start search point.

=item filter => ( a string )

A filter is a string which format complies the RFC1960.

B<Example>

  (cn=Babs Jensen)
  (!(cn=Tim Howes))
  (&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))
  (o=univ*of*mich*)

=item scope => 'base' | 'one' | 'sub'

The default value is 'sub' which means it will search all subtrees. 'base' means only 
search the base object. 'one' means only search one level below the base object.

=item sizelimit => ( number )

A sizelimit is the maximum number of entries will be returned as a result of the 
search. The default value is 0, denots no restriction is applied.

=item attrs => ( attributes )

A list of attributes to be returned for each entry. The value is normally a reference 
to an array which contains the preferred attributes.

B<Example>

  $msg = $ldap->search( base      => 'ou=language,dc=shallot,dc=com',
						filter    => '(|(cn=aperture)(cn=shutter_speed))',
						scope     => 'one',
						sizelimit => 0,
						attrs     => \@attrs
						);

=back

=item compare ( DN, OPTIONS )

Compare values in an attribute in the entry given by DN on the server. DN is a string.
If the compare is failed, errstr() method can be used to fetch the reason for the failure.

=over 4

=item attrs => attributeType

The name of the attribute type to compare.

=item value => attributeValue

The attribute value to compare with.

B<Example>

  if (!defined $ldap->compare('ou=people,dc=shallot,dc=com',
          attr  => 'objectClass',
          value => 'top'
      )) {
      print $ldap->errstr;
  }

=back

=item add ( DN, OPTIONS )

Add a new entry to the LDAP directiory. DN is a string.

=over 4

=item attrs => VALUE

C<VALUE> should be a hash reference.

B<Example>

  my %attrs = (
    uid => 'Lionel',
    cn  => 'Lionel',
    sn  => 'Luthor',
    uidNumber    => '65534',
    gidNumber    => '65534',
    homeDirectory => '/home/Lionel',
    loginShell  => '/bin/bash',
    objectClass => [qw(inetOrgPerson posixAccount top)]
  );

  $ldap->add( 'uid=Lionel,ou=people,dc=shallot,dc=com',
              attrs => \%attrs
            );

=head1 DEVELOPMENT STAGE

This module is still under development. The basic features in terms of binding and 
searching result have been done. Further functions such as add, delete and modify 
entries will be provided soon.

=head1 BUGS and RECOMMENDATIONS

Any bugs and recommendation is welcome. Please send directly to my email address 
listed below. Bugs and functions will be updated at least every one month. 

=head1 ACKNOWLEDGEMENTS

A special thanks to Larry Wall <larry@wall.org> for convincing me that no 
development could be made to the Perl community without everyone's contribution.

=head1 AUTHOR

Pan Yu <xiaocong@vip.163.com>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008-2009 by Pan Yu. All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
