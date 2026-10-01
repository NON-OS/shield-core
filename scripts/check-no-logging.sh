#!/usr/bin/env bash
# Nothing in the wallet core writes to a log.
#
# A log on a phone is readable by whoever holds it, and by a crash reporter, a
# backup, and on some devices another app. The brief says logging is off in
# release and stripped from the binary rather than filtered at runtime, and the
# way to keep that true is for the code to have no logging in it at all.
#
# This greps the source rather than the binary, because a macro that is
# compiled out still says somebody meant to log a balance, and the next person
# who removes the feature flag ships it.
set -euo pipefail

cd "$(dirname "$0")/.."

sources=$(find core/src field-kernel/src -name '*.rs' 2>/dev/null)
if [ -z "$sources" ]; then
    echo "no sources found" >&2
    exit 1
fi

# Nothing that ships prints. The log crate is matched by its macros rather than by its name, because the
# note store's own module is called log and a name match reports that forever.
found=0
for macro in 'println!' 'eprintln!' 'dbg!' 'print!' 'eprint!' \
    'log::trace!' 'log::debug!' 'log::info!' 'log::warn!' 'log::error!' \
    'tracing::' 'os_log' 'android_log'
do
    hits=$(grep -n -- "$macro" $sources || true)
    if [ -n "$hits" ]; then
        echo "the core writes output with $macro:" >&2
        echo "$hits" >&2
        found=1
    fi
done

[ "$found" -eq 0 ] || exit 1
echo "the core writes to no log, no terminal and no debug macro"
