#!/bin/bash

D=`dirname "$0"`

MKEY=$D/mkey/ccn-publish-key.sh
KEYSTORE=$D/site-keystore/
AFFI=UCLA
VALID_DAYS=365
SIGNING_KEY_NAME=/ndn/keys/ucla.edu
KEY_PREFIX=/ndn/keys/ucla.edu
CERTS=$D/certs

SYNC_TOPO_PREFIX="/ndn/broadcast/sync/keys"
SYNC_NAME_PREFIX="/ndn/keys"

function usage {
            cat <<EOF
Usage:  
  $0 [-h] (-s | -S)
      Sign user public keys

      -h print this help message
      -S sign and publish user public keys (*.pem) located in ${CERTS} folder
      -s create sync slice and exit
EOF
            exit 1
}

while getopts "hs" flag; do
    case "$flag" in
	s) 
            echo Creating repo slice
            ccnsyncslice create "$SYNC_TOPO_PREFIX" "$SYNC_NAME_PREFIX"
            RET=$?
            echo "Status of ccnsyncslice create: $RET"
            exit 0
            ;;
	S)
	    for cert in `ls ${CERTS}/*.pem 2>/dev/null`; do
		USER=`basename $cert .pem`
		$MKEY -i $USER -a $AFFI -f $cert -F $KEYSTORE -P $SIGNING_KEY_NAME -p ${KEY_PREFIX}/${USER} -x $VALID_DAYS && echo "Signed $USER"
	    done
	    exit 0
	    ;;
        *)
	    usage
	    ;;
    esac
done

usage