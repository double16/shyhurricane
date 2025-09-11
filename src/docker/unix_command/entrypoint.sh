#!/usr/bin/env bash

# The LLMs really want to save files in /tmp, even though we've instructed them to use the CWD. We need to keep
# /tmp files over container invocations. Bind mount requires CAP_SYSADMIN which we don't want. We can't replace
# /tmp with a symlink because we need to run as root. So we're syncing files between /tmp (and /var/tmp for good
# measure) before and after the command invocation. *sigh

KEEP_DIRS="/tmp /var/tmp"

for D in ${KEEP_DIRS}; do
  WD="./.private${D}"
  if [ -d "${WD}" ]; then
    rsync --archive --quiet "${WD}/" "${D}/" >/dev/null 2>/dev/null
  fi
done

"$@"
RET=$?

for D in ${KEEP_DIRS}; do
  WD="./.private${D}"
  if [ -d "${WD}" ]; then
    rsync --archive --quiet "${D}/" "${WD}/" >/dev/null 2>/dev/null
  fi
done

exit $RET
