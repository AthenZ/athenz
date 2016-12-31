#!/usr/local/bin/perl -w

use strict;

my $ROOT = $ENV{ROOT};
if (!$ROOT) {
    $ROOT = "/home/athenz";
}

my $num_args = $#ARGV + 1;
if ($num_args != 1) {
    exit 1;
}

my $zpu_user = $ARGV[0];

system("chown -R $zpu_user $ROOT/var/zpe");
my $ret = $?;
if ($ret != 0) {
    print "Unable to chown $zpu_user for file $ROOT/var/zpe\n";
    exit 2;
}
# before running chown on tmp/zpe directory
# make sure it exists. it's possible that 
# it was cleaned up which is ok since zpu
# will create it with the ownership of the
# running user when it gets executed
if (-d "$ROOT/tmp/zpe") {
    system("chown -R $zpu_user $ROOT/tmp/zpe");
    $ret = $?;
    if ($ret != 0) {
        print "Unable to chown $zpu_user for file $ROOT/tmp/zpe\n";
        exit 3;
    }
}
system("chown -R $zpu_user $ROOT/logs/zpe_policy_updater");
$ret = $?;
if ($ret != 0) {
    print "Unable to chown $zpu_user for file $ROOT/logs/zpe_policy_updater\n";
    exit 4;
}
exit 0;
