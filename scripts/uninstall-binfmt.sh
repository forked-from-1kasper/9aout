#! /bin/sh
if [ -e /proc/sys/fs/binfmt_misc/plan9 ]; then
    echo -1 > /proc/sys/fs/binfmt_misc/plan9
fi