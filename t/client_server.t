#!/usr/bin/env perl

use Mojolicious::Lite;
use Test::Mojo;
use Test::More;
use Test::Exception;

my $t=Test::Mojo->new;
my $host = $t->ua->server->url->host;
my $port = $t->ua->server->url->port;

use_ok "MojoX::OAuth2::Client";
my $client = new_ok "MojoX::OAuth2::Client";

my $idp_config = {
    test_idp => {
        scope         => 'http://scope1,scope2',
        client_id     => 'fake_id',
        client_secret => 'fake_secret',
        authorize_url => Mojo::URL->new("http://$host:$port/fake_auth"),
        token_url     => Mojo::URL->new("http://$host:$port/fake_token"),
    }
};

$client->identity_providers( $idp_config );

get '/fake_auth' => sub {
    my $self = shift;
    my $return = Mojo::URL->new($self->param('redirect_uri'));
    $return->query->append(code => 'fake_code');
    $self->redirect_to($return);
};

post 'fake_token' => sub {
    my $self = shift;
    my %token = ( 
        access_token => 'fake_token', 
        expires_in => '3600',
        token_type   => 'Bearer',
    );
    $self->render( json => \%token);
};


get '/code_callback' => sub {
    my $self = shift;
    $self->render_later;
    $client->receive_code( $self->req->params->to_hash )->on(
        access_denied => sub {
            my ($client, $error) = @_;
            $self->render_exception($error->{error_description})
        },
        error => sub {
            my ($client, $error) = @_;
            $self->render_exception($error->{error_description})
        },
        success => sub {
            my ($client, $code) = @_;
            $self->render( text => $code);
        },
    )->execute;
};

test_get_authorization_url();
test_get_authorization_code();
test_get_token();

sub test_get_authorization_url {
    my $auth_url = $client->provider('test_idp')->get_authorization_url;
    like($auth_url, qr{^http://$host:$port/fake_auth}, 'got correct authorize url');
    is($auth_url->query->param('scope'), 'http://scope1,scope2', 'get_authorization_url has correct scope');
    is($auth_url->query->param('client_id'), 'fake_id', 'get_authorization_url has correct client_id');
}

sub test_get_authorization_code {
    my $redirect_uri = "http://$host:$port/code_callback";
    my $auth_url = $client->provider('test_idp')->get_authorization_url(redirect_uri => $redirect_uri );
    is($auth_url->query->param('redirect_uri'), $redirect_uri, 'get_authorization_url with custom redirect_uri');

    $t->get_ok($auth_url)->status_is(302);
    my $res = Mojo::URL->new($t->tx->res->headers->location);
    is($res->path, Mojo::URL->new($redirect_uri)->path, 'code request returns to specified redirect_uri');
    $t->get_ok($res)->status_is(200);
    my $code = $t->tx->res->body;
    is($code, 'fake_code', 'correct code is returned');
}

sub test_get_token {
    $client->provider('test_idp')->get_token(code => 'fake_code')->on(
        success => sub {
            my ($client, $response) = @_; 
            is( ref($response), 'HASH', 'get_token success returned HASH' );
            is($response->{access_token}, 'fake_token', 'get_token success returned access_token');
            Mojo::IOLoop->stop;
        },
        failure => sub {
            my ($client, $error) = @_;
            diag Dumper $error;
            fail("get_token returned failure but expected success");
            Mojo::IOLoop->stop;
        },
    )->execute;
    
    Mojo::IOLoop->start unless Mojo::IOLoop->is_running;
}

done_testing;
