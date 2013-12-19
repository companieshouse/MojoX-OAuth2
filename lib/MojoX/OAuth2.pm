package MojoX::OAuth2;

our $VERSION = '0.01';

use MojoX::OAuth2::Client::Client;
use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app, $options) = @_;

    $self->mango($options->{mango});

    $app->helper(mongodb => sub {
        my ($controller, $db, $collection) = @_;
        return $self->wrap_mango($db, $collection);
    });
}

sub wrap_mango {
    my ($self, $db, $collection) = @_;

    ($db, $collection) = $db =~ /([^\.]+)\.([^\.]+)/ if $db =~ /\./ and !$collection;

    return new Mojolicious::Plugin::MangoWrapper::CollectionWrapper->new(
        collection => $self->mango->db($db)->collection($collection)
    );
}

1;

=encoding utf8

=head1 NAME

Mojolicious::Plugin::MangoWrapper- A Mojolicious wrapper for Mango

=head1 DESCRIPTION

L<Mojolicious::Plugin::MangoWrapper> provides a wrapper to L<Mango> and
L<Mango::Collection> objects to provide a cleaner interface and to
enforce the use of non-blocking L<Mango> calls.

=head1 ATTRIBUTES

L<Mojolicious::Plugin::MangoWrapper> implements the following attributes.

=head2 collection

    my $collection = $wrapper->collection;
    $queue->collection($mango->db('foo')->collection('bar'));

The L<Mango::Collection> used by chained operations.

=head1 METHODS

L<Mojolicious::Plugin::MangoWrapper> implements the following methods.

=head2 register

    $app = Mojolicious->new;
    $wrapper->register($app, { mango => Mango->new });

Registers a Mojolicious helper method to return a wrapped L<Mango::Collection>.

=head2 wrap_mango

    $wrapped = $wrapper->wrap_mango('db', 'collection');
    $wrapped = $wrapper->wrap_mango('db.collection');

Wraps a L<Mango::Collection> for the provided database and collection.

=head1 SEE ALSO

L<Mojolicious>, L<Mango>

=cut
