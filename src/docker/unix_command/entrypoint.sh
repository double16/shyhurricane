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

# Create FIFOs for live mirroring to tee
stdout_fifo=$(mktemp -u)
stderr_fifo=$(mktemp -u)
mkfifo "$stdout_fifo" "$stderr_fifo"

# Start tee processes:
#  - stdout: write log AND mirror to original stdout
#  - stderr: write log AND mirror to original stderr
tee "${STDOUT_LOG:-/dev/null}" <"$stdout_fifo" >&1 &
tee_pid_out=$!
tee "${STDERR_LOG:-/dev/null}" <"$stderr_fifo" >&2 &
tee_pid_err=$!

# Redirect the script’s stdout/stderr into the FIFOs
exec 1>"$stdout_fifo" 2>"$stderr_fifo"

# Ensure we clean up even on error/exit
cleanup() {
  # Close current stdout/stderr to send EOF to tee
  exec 1>&- 2>&-
  # Wait for tee to flush and exit
  wait "$tee_pid_out" "$tee_pid_err" 2>/dev/null || true
  # Remove FIFOs
  rm -f "$stdout_fifo" "$stderr_fifo" || true
}
trap cleanup EXIT


"$@"
RET=$?

for D in ${KEEP_DIRS}; do
  WD="./.private${D}"
  if [ -d "${WD}" ]; then
    rsync --archive --quiet "${D}/" "${WD}/" >/dev/null 2>/dev/null
  fi
done

exit $RET
