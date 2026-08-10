#!/bin/bash
cd "$(dirname "$0")"
groff -man -Tutf8 -ww -b burncracker.1 > /tmp/out.txt 2> /tmp/err.txt
echo "exit code: $?"
if [ -s /tmp/err.txt ]; then
    echo "--- warnings/errors ---"
    cat /tmp/err.txt
else
    echo "no warnings"
fi
