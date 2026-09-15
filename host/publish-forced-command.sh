#!/bin/sh
# Forced command for the restricted CI publisher key.
#
# The key may only ever run the publisher: no shell, no other program, and only
# the fixed remote script with its four validated arguments.
set -eu

original=${SSH_ORIGINAL_COMMAND:-}
case "$original" in
  'python3 /home/siel/bin/lapkb-publish-remote.py '*) ;;
  *)
    echo 'restricted publisher: unexpected command' >&2
    exit 64
    ;;
esac

arguments=${original#'python3 /home/siel/bin/lapkb-publish-remote.py '}
# shellcheck disable=SC2086 # intentional word splitting of validated arguments
set -- $arguments
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo 'restricted publisher: expected <root> <app> <channel> [legacy]' >&2
  exit 64
fi

case "$1" in
  /home/siel/*) ;;
  *)
    echo 'restricted publisher: unexpected root' >&2
    exit 64
    ;;
esac

exec /usr/bin/python3 /home/siel/bin/lapkb-publish-remote.py "$@"
