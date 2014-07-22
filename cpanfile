requires 'Mojo::Base';
requires 'Mojo::UserAgent';
on 'test' => sub {
  requires 'Mojolicious::Lite';
  requires 'Test::Exception';
  requires 'Test::Mojo';
};
