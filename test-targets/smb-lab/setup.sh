#!/bin/bash
mkdir -p /srv/smb/public
echo "TOP_SECRET=hunter2" > /srv/smb/public/creds.env
mkdir -p /srv/smb/public/keys
echo "PRIVATE KEY DATA" > /srv/smb/public/keys/id_rsa

