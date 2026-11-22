# SPDX-License-Identifier: AGPL-3.0-only
# Used only by the Linux recovery probe on its disposable ordinary object.
use strict;
use warnings;
use Fcntl qw(O_RDONLY O_NOFOLLOW O_NONBLOCK F_SETLEASE F_WRLCK F_UNLCK);

$| = 1;
my ($opened, $release) = (0, 0);
$SIG{IO} = sub { $opened = 1 };
$SIG{USR1} = sub { $release = 1 };
$SIG{ALRM} = sub { die "object hold timed out\n" };
$SIG{TERM} = sub { exit 1 };
open my $timeout_file, '<', '/proc/sys/fs/lease-break-time' or die "lease timeout unavailable\n";
my $timeout = <$timeout_file>;
close $timeout_file;
chomp $timeout;
$timeout =~ /\A[0-9]+\z/ && $timeout > 1 or die "invalid lease timeout\n";
@ARGV == 1 or die "expected fixture object\n";
sysopen my $file, $ARGV[0], O_RDONLY | O_NOFOLLOW | O_NONBLOCK
    or die "fixture object unavailable\n";
-f $file && -o $file or die "unexpected fixture object\n";
fcntl($file, F_SETLEASE, F_WRLCK) or die "could not lease fixture object\n";
alarm 90;
print "ready\n";
sleep 1 until $opened;
# The kernel bounds lease breaks. Fail before an unobserved automatic release.
alarm($timeout - 1);
print "blocked\n";
sleep 1 until $release;
fcntl($file, F_SETLEASE, F_UNLCK) or die "could not release fixture object\n";
close $file;
alarm 0;
print "released\n";
