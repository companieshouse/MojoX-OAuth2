#!/usr/bin/env perl

use Test::More;
use Test::Exception;
use Data::Dumper;

use_ok "MojoX::OAuth2::Client";

my $client;

my $idp_config = {
    test_idp => {
        redirect_uri => 'urn:ietf:wg:oauth:2.0:oob',
        scope => 'http://scope',
        client_id => '396237516018.apps.ch.gov.uk',
        client_secret => 'wnWxvcA64idqJn3knfXeDHCqCnYALfj8iKoWCWPtI2I',
        authorize_url => 'http://accounts.orctel.internal:9502/oauth2/authorise',
        token_url     => 'http://accounts.orctel.internal:9502/oauth2/token',
    }
};

my $access_token = '2yOTNFZFEjr1zCsicMWpAA';

$client = new_ok "MojoX::OAuth2::Client";
$client->identity_providers( $idp_config );
$client->provider('test_idp')->get_token->on(
    success => sub { 
        my ($client, $response) = @_;
        Mojo::IOLoop->stop;

        is( ref($response), 'HASH', 'get_token success returned HASH' );
        is( $response->{access_token}, $access_token, 'get_token success returned access_token' );
    },
    access_denied => sub { 
        my ($client, $error) = @_;
        Mojo::IOLoop->stop;
        diag Dumper $error;
        fail("get_token returned access_denied but expected success");
    },
    failure => sub { 
        my ($client, $error) = @_;
        Mojo::IOLoop->stop;
        diag Dumper $error;
        fail("get_token returned failure but expected success");
    } 
)->execute;

Mojo::IOLoop->start;

done_testing;
