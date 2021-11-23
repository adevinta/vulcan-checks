#!/bin/bash

# If LINKING_KEY is not provided do not start
# Nessus agent in the local container.
if [ -n "$LINKING_KEY" ]; then
    supervisord -c /etc/supervisord.conf &
fi
./vulcan-nessus
