#!/bin/bash

supervisord -c /etc/supervisord.conf &
./vulcan-nessus
