#!/bin/sh
# Restricted publisher key: only the fixed framed receiver, never administration.
set -eu

if [ "${SSH_ORIGINAL_COMMAND:-}" != 'python3 /home/siel/bin/publish_remote.py --receive-v1' ]; then
  echo 'restricted publisher: unexpected command' >&2
  exit 64
fi

exec /usr/bin/python3 /home/siel/bin/publish_remote.py --receive-v1
