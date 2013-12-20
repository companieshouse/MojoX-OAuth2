package MojoX::OAuth2::Client;

use Mojo::Base 'Mojo::EventEmitter';
use Mojo::UserAgent;

has 'operations' => sub { [] };
has 'error';
has 'code';
has 'state';


has 'identity_providers';
has '_provider';

#-------------------------------------------------------------------------------

sub on {
    my ($self, %events) = @_;

    for my $event (keys %events) {
        $self->SUPER::on($event => $events{$event});
    }

    return $self;
}

#-------------------------------------------------------------------------------

sub provider {
    my ($self, $provider) = @_;

    die "Unknown provider '$provider' requested" unless exists $self->identity_providers->{$provider};

    # Set IDP config hash as provider
    $self->_provider( $self->identity_providers->{$provider} );

    return $self;
}

#-------------------------------------------------------------------------------

sub get_authorization_url
{
    my ($self, %args) = @_;

    my $redirect_uri  = $args{redirect_uri}  // $self->_provider->{redirect_uri};
    my $response_type = $args{response_type} // 'code';
    my $scope         = $args{scope}         // $self->_provider->{scope} // '';
    my $client_id     = $self->_provider->{client_id};
    my $auth_url      = $self->_provider->{authorize_url};

    delete $args{redirect_uri};
    delete $args{response_type};
    delete $args{scope};

    # authorisation request is a GET
    my $url = Mojo::URL->new( $auth_url );

    # Mandatory parameters
    $url->query->append( client_id     => $client_id     );
    $url->query->append( redirect_uri  => $redirect_uri  );
    $url->query->append( response_type => $response_type );

    # Optional parameters
    $url->query->append( scope => $scope         ) if $scope;

    # Append any further args that may have been passed in, including state.
    foreach my $opt_arg (keys %args)
    {
        $url->query->append( $opt_arg => $args{$opt_arg} );
    }

    return $url;
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
# Params passed back from OAuth2 server will be x-form-url-encoded
# (usually as part of the query string but could be a post)
# so parameters need to be extracted into a hash by the caller.
#
sub receive_code {
    my ($self, $params) = @_;

    push @{$self->operations}, sub
    {
        my $errors = $self->_extract_errors( $params );

        $self->code ( $params->{code} );
        $self->state( $params->{state} ) if $params->{state};

        # If we are not chaining to a get_token operation, deal with callbacks here.
        if( not @{$self->operations} ) {
            return $self->emit_safe('access_denied' => $errors ) 
                    if $errors && $errors->{error} eq 'access_denied' && $self->has_subscribers('access_denied');
            return $self->emit_safe('failure' => $errors) if $errors;
            return $self->emit_safe('success' => $self->code );
        }
    };

    return $self;
}

#-------------------------------------------------------------------------------

sub get_token {
    my ($self, %args) = @_;

    push @{$self->operations}, sub {

        my $params;
        my $grant_type = $args{grant_type} || 'authorization_code';
        my $assertion  = $args{assertion};

        if( $grant_type eq 'authorization_code' )
        {
            $params = {
                grant_type    => $grant_type,
                code          => $args{code} // $self->code,
                client_id     => $self->_provider->{client_id},
                client_secret => $self->_provider->{client_secret},
                redirect_uri  => $self->_provider->{redirect_uri},
            };
        }

        if( $grant_type =~ /^[urn|http]/ )
        {
            $params = {
                grant_type => $grant_type,
                assertion  => $assertion,
                # 'urn:ietf:params:oauth:grant-type:jwt-bearer'
            };
        }

        die "unsupported grant_type '$grant_type'" unless $params;

        my $token_url = $self->_provider->{token_url};

        die "Missing token_url in identity provider configuration" unless $token_url;

        my $ua = Mojo::UserAgent->new;
        $self->_post( $ua, $token_url, $params, sub {
            my( $success, $error ) = @_;

            $ua = $ua; # XXX ua goes out of scope, so need to do this

            return $self->emit_safe('success' => $success ) if $success;
            return $self->emit_safe('failure' => $error );
        });
    };

    return $self;
}

#-------------------------------------------------------------------------------

sub _post
{
    my( $self, $ua, $url, $params, $cb ) = @_;

    $ua->post( $url, form => $params => sub {
        my ($client, $tx) = @_;

        my $success_json = $tx->success->json if $tx->success;
        my $error;

        if( $tx->error )
        {
            my ( $error_desc, $error_uri );
            my ( $error_text, $status_code ) = $tx->error;

            if( $status_code ) {
                # Errors are returned as a JSON doc from OAuth2 POST methods
                $error_text = $tx->res->json('/error');
                $error_desc = $tx->res->json('/error_description');
                $error_uri  = $tx->res->json('/error_uri');
            } else {
                $error_text = 'connection_error';
            }

            my $error_hash = {
                error             => $error_text,
                error_description => $error_desc,
                error_uri         => $error_uri, 
                status            => $status_code,
            };
            $error = $self->_extract_errors( $error_hash );
        }

        $cb->( $success_json, $error );
    });
}

#-------------------------------------------------------------------------------

sub _extract_errors
{
    my ($self, $response) = @_;

    my %errors;
    if( ref($response) eq 'HASH' && $response->{error} )
    {
        $errors{error}             = $response->{error};
        $errors{error_description} = $response->{error_description} if $response->{error_description};
        $errors{error_uri}         = $response->{error_uri}         if $response->{error_uri};
        $errors{status}            = $response->{status}            if $response->{status};

        $self->error( \%errors );
        return \%errors;
    }
    return undef;
}

#-------------------------------------------------------------------------------

1;
