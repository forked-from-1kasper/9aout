#! /bin/sh
if ! [ -e /proc/sys/fs/binfmt_misc/plan9 ]; then
    echo ":plan9:M::\x00\x00\x8a\x97::$(realpath 9aout):P" > /proc/sys/fs/binfmt_misc/register
fi