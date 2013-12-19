package MojoX::OAuth2::Client::Client;

use Mojo::Base 'Mojo::EventEmitter';
use Mojo::UserAgent;

has 'operations' => sub { [] };
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

    # Set IDP config hash as provider
    $self->_provider( $self->identity_providers->{$provider} );

    return $self;
}

#-------------------------------------------------------------------------------

sub get_authorization_url
{
    my ($self, %args) = @_;

    my $redirect_url  = $args{redirect_url}  // $self->_provider->{redirect_url};
    my $response_type = $args{response_type} // 'code';
    my $scope         = $args{scope}         // $self->_provider->{scope} // '';
    my $client_id     = $self->_provider->{client_id};
    my $auth_url      = $self->_provider->{authorize_url};

    delete $args{redirect_url};
    delete $args{response_type};
    delete $args{scope};

    # authorisation request is a GET
    my $auth_url = Mojo::URL->new( $auth_url );

    # Mandatory parameters
    $auth_url->query->append( client_id     => $client_id     );
    $auth_url->query->append( redirect_url  => $redirect_url  );
    $auth_url->query->append( response_type => $response_type );

    # Optional parameters
    $auth_url->query->append( scope => $scope         ) if $scope;

    # Append any further args that may have been passed in, including state.
    foreach my $opt_arg (keys %args)
    {
        $auth_url->query->append( $opt_arg => $args->{$opt_arg} );
    }

    return $auth_url;
}

#-------------------------------------------------------------------------------

sub execute {
    my ($self) = @_;

    die("No operation") unless @{$self->operations};

    
    while( !$self->error && @{$self->operations} )
    {
        shift->();
    }
}


#-------------------------------------------------------------------------------
# Params passed back from OAuth2 server will be x-form-url-encoded
#
sub recieve_code {
    my ($self, $params) = @_;

    push @{$self->operations}, sub
    {
        my $errors = $self->_extract_errors( $param );

        $self->code ( $params->{code} );
        $self->state( $params->{state} ) if $params->{state};

        # If we are not chaining to a get_token operation, deal with callbacks here.
        if( not @{$self->operations} ) {
            return $self->emit_safe('access_denied' => $errors ) 
                    if $errors && $errors->{error} eq 'access_denied' && $self->has_subscribers('access_denied');
            return $self->emit_safe('failure' => $errors) if $errors;
            return $self->emit_safe('success' => $self->result );
        }
    };

    return $self;
}

#-------------------------------------------------------------------------------

sub get_token {
    my ($self, %args) = @_;

    push @{$self->operations}, sub
    {
        my $ua = Mojo::UserAgent->new;

        my $params;
        my $grant_type = $args{grant_type} || 'authorization_code';
        my $assertion  = $args{assertion};

        if( $grant_type eq 'authorization_code' )
        {
            $params = {
                code          => $args{code} // $self->code;,
                client_id     => $self->_provider->{client_id},
                client_secret => $self->_provider->{client_secret},
                redirect_url  => $self->_provider->{redirect_url},
                grant_type    => $grant_type
            };
        }

        if( $assertion )
        {
            $params = {
                assertion  => $assertion,
                grant_type => $grant_type
                # 'urn:ietf:params:oauth:grant-type:jwt-bearer'
            };
        }


        die "unsupported grant_type '$grant_type'" unless $params;

        $us->on( error => sub {
            my( $ua, $err ) = @_;
            # TODO make $err consistent with all other data passed to failure callback
            return $self->emit_safe('failure' => $err );
        } );

        $ua->post( $self->_provider->{token_url}, form => $params => sub {
            my ($client, $tx) = @_;
                if( my $res = $tx->success ) { return $self->emit_safe('success' => $res->json ) };

                my $errors = $self->_extract_errors( $tx->error ); # FIXME  what  does $tx->error look like??

                return $self->emit_safe('failure' => $errors );
            }
        );
    };

    return $self;
}

#-------------------------------------------------------------------------------

sub _extract_errors
{
    my ($self, $resp) = @_;

    my %errors;
    if( $params->{error} )
    {
        $errors{error}             = $params->{error};
        $errors{error_description} = $params->{error_description} if $params->{error_description};
        $errors{error_uri}         = $params->{error_uri}         if $params->{error_uri};
        #  FIXME Add status code for other types of failure
    }

    $self->error( \%errors );

    return \%errors;
}

#-------------------------------------------------------------------------------

1;
