package MojoX::OAuth2::Profile;

use Mojo::Base 'Mojo::EventEmitter';
use Mojo::UserAgent;

has 'operations' => sub { [] };

has 'identity_providers';
has '_provider';

#-------------------------------------------------------------------------------

sub on {
    my ($self, %events) = @_;

    for my $event (keys %events) {
        $self->SUPER::on($event => $events{$event});
    }

    if( ! $self->has_subscribers('error') ) {
        $self->SUPER::on(error => sub {
            my ($self, $error) = @_;
            print "Error $error";
        });
    }

    return $self;
}

#-------------------------------------------------------------------------------

sub provider {
    my ($self, $provider) = @_;

    die "Unknown provider '$provider' requested" unless exists $self->identity_providers->{$provider};

    $self->_provider($self->identity_providers->{$provider});

    return $self->new(
        identity_providers => $self->identity_providers,
        _provider => $self->identity_providers->{$provider},
    );
}

#-------------------------------------------------------------------------------

sub execute {
    my ($self) = @_;

    die("No operation") unless @{$self->operations};

    while( @{$self->operations} )
    {
        shift( @{$self->operations} )->();
    }
}

#-------------------------------------------------------------------------------

sub fetch {
    my ($self, %args) = @_;

    push @{$self->operations}, sub {


        my $profile_url = $self->_provider->{profile_url};

        die "Missing profile_url in identity provider configuration" unless $profile_url;

        my $ua = Mojo::UserAgent->new;

        my $token = $args{token};
        my $type  = $args{type} || 'Bearer';

        $ua->on( start => sub {
            my ($ua, $tx) = @_;
            $tx->req->headers->header('Authorization' => "$type $token");
            $tx->req->headers->header('Accept'        => "application/json");
        } );

        $ua->get($profile_url => sub {
            my ($client, $tx) = @_;

            $ua = $ua;

            return $self->emit('failure' => $tx->error ) if $tx->error;

            my $profile_json = $tx->success->json if $tx->success;
            return $self->emit('success' => $profile_json );
        });
    };

    return $self;
}

#-------------------------------------------------------------------------------

1;

=encoding utf8

=head1 NAME

MojoX::OAuth2 - Mojo::IOLoop based OAuth 2.0 implementation

=head1 SYNOPSIS

    use MojoX::OAuth2::Client;

    my $client = MojoX::OAuth2::Client->new();

    # Set up configuration of all identity providers
    $client->identity_providers( \%identity_providers );

    # To select which identity provider to use
    $client->provider('some_provider_name');

    # Request user authorisation via a given identity provider
    my $redirect_url = $client->get_authorization_url( state => 'some_state' );

    # ... redirect browser to $redirect_url to complete authentication

    # If OAuth2 server returns by calling back to a URL, then the code is picked up with this
    # (with non-blocking callbacks):
    #
    $client->receive_code( \%input_parameters_from_http[s]_request )->on(
        access_denied => sub { },
        failure       => sub { },
        success       => sub { }
    )->execute;

    # If the OAuth2 server generated authorisation_code is aquired through some other means, it must be 
    # given to the OAuth2 client before an access_token can be requested:
    $client->code('the_authorisation_code'); # Set the authorisation code

    # To exchange a code for an access_token (which uses non-blocking callbacks):
    $client->get_token->on(
        access_denied => sub { },
        failure       => sub { },
        success       => sub { }
    )->execute;

    # Alternatively, some of the above steps can be combined:
    my $redirect_url = $client->provider('some_provider_name')->get_authorization_url( state => 'some_state' );

    $client->provider('some_provider_name')->receive_code->get_token->on(
        access_denied => sub { },
        failure       => sub { },
        success       => sub { }
    )->execute;

=head1 DESCRIPTION

An Mojo::IOLoop based, non-blocking, OAuth 2.0 client.

=head1 METHODS

L<MojoX::OAuth2::Client> implements the following methods:

=head2 identity_providers

Configure OAuth2 client with the supported identity providers. The configuration hash takes the following form:

    {
        identity_provider_one => {
            redirect_uri  => 'callback_url',
            scope         => 'default_scope. May be overridden in get_authorisation',
            client_id     => 'The id allocated to the client by OAuth2 server when it was registered',
            client_secret => 'The id allocated to the client by OAuth2 server when it was registered',
            authorize_url => 'The OAuth2 servers authorisation request URL',
            token_url     => 'The OAuth2 servers token request URL'
        },
        identity_provider_two   => { },
        identity_provider_three => { },
    }

=head2 provider

Chooses the identity provider to engage with. May be called directly on the client instance, or inline with other methods.

=head2 get_authorization_url

Returns the URL that the users browser should be [re]directed to. This begins the authorisation process which culminates in
an authorisation code being generated in response to a sucessful user authentication.

The method takes the following optional named arguments:

=over 2

=item * redirect_uri

Overrides the redirect_uri given in the identity provider configuration.

=item * response_type

Defaults to C<code>.

=item * scope

An application specific string that will be returned by a fully complient OAuth2 server in both successful
and failed/denied authorisations.

=back

=head2 receive_code

Takes a hash (ref) of parameters, usually received from the HTTP callback request made by the OAuth2 server, from which it extracts the authorisation code parameter. The parameter value is used by subsequent access_token requests.
The execution of the code receipt is deferred until the L</execute> method is called which requires that three callback subroutines are provided through the L</on> method,
one of which will be invoked to handle the result of the code receipt.

Alternatively, the C<code> property of the client may be set directly, allowing other methods of receipt.

=head2 get_token

This method puts the client in "request access token" mode. 
The token request is deferred until the L</execute> method is called which requires that three callback subroutines are provided through the L</on> method.
When L</execute> is invoked, the identity provider OAuth2 server is contacted and the authorisation code to access token exchange is requested, 
resulting in one of the callback subroutines being called.

=head2 on

Register three callback subroutines with the client, one of which will receive the response of the receive_code or get_token method call, once L</execute> is invoked.
The named subroutines are:

=over 4

=item success

This subroutine is called when an access_token is successfully received. It is passed the client instance and the returned access_token docuemnt (hash ref).

    success => sub {
        my ( $client, $response ) = @_;
    }

=item access_denied

This subroutine is called if a user authorisation is denied or cancelled by the user. It is passed the client instance and the error response document

    access_denied => sub {
        my ( $client, $error ) = @_;
    }

The error document can contain:

=over 2

=item * error

The error that was returned, such as C<access_denied>.

=item * error_description

An optional error description string.

=item * status

The HTTP status code returned.

=item * error_url

An optional URL giving further details or a complete description of the error.

=back

=item failure

This subroutine is called if a user authorisation failsis denied or cancelled by the user. It is passed the client instance and the error response document

    failure => sub {
        my ( $client, $error ) = @_;
    }

The error document has the same content as described by the L</access_denied> callback above.

=item execute

Execute the deferred receive_token, get_token (or both, in sequence) invoking the appropriate callback subroutine to handle the final result.

=back

=cut
