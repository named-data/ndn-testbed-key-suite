#!/bin/sh

D=`dirname "$0"`

MKEY=$D/mkey/ccn-publish-key.sh
KEYSTORE=$D/site-keystore/
AFFI=UCLA
VALID_DAYS=365
SIGNING_KEY_NAME=/ndn/keys/ucla.edu
KEY_PREFIX=/ndn/keys/ucla.edu
CERTS=$D/certs

for cert in ${CERTS}/*
do
  USER=`basename $cert .pem`
  $MKEY -i $USER -a $AFFI -f $cert -F $KEYSTORE -P $SIGNING_KEY_NAME -p ${KEY_PREFIX}/${USER} -x $VALID_DAYS && echo "Signed $USER"
done
