#! /bin/sh
if [ -e /proc/sys/fs/binfmt_misc/plan9 ]; then
    echo -1 | sudo tee /proc/sys/fs/binfmt_misc/plan9 > /dev/null
fi