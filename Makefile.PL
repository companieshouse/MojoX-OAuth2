#!perl -w

###############################################################################
##                                                                           ##
##    Copyright (c) 2014 Companies House                                     ##
##    All rights reserved.                                                   ##
##                                                                           ##
##    This package is free software; you can redistribute it                 ##
##    and/or modify it under the same terms as Perl itself.                  ##
##                                                                           ##
###############################################################################

use strict;
use ExtUtils::MakeMaker;

BEGIN
{
    eval { require Config_m; }; # ExtUtils::FakeConfig (+ ActivePerl)
    eval { require Config;   } # Everyone else
    if ($@);
}

WriteMakefile(
    'NAME'          => 'MojoX::OAuth2',
    'VERSION_FROM'  => 'lib/MojoX/OAuth2.pm',
    'ABSTRACT_FROM' => 'lib/MojoX/OAuth2.pm',
    'LICENSE'       => 'perl',
    'AUTHOR'        => 'Companies House <chgovuk@cpan.org>',
    'PREREQ_PM'     => {
                           'Moose' => '2.0603'
                       },
    'dist'          => { COMPRESS => "gzip -9", SUFFIX => "gz" },
#   for ActivePerl:
       ($] >= 5.005 && $^O eq 'MSWin32' && $Config::Config{'archname'} =~ /-object\b/i ?
               ('CAPI'         => 'TRUE') : ())
);

__END__
