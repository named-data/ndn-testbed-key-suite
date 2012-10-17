#!/bin/bash

D=`dirname "$0"`

MKEY=$D/mkey/ccn-publish-key.sh
KEYSTORE=$D/site-keystore/
AFFI=${AFFI:-"UCLA"}
VALID_DAYS=365
SIGNING_KEY_NAME=${SIGNING_KEY_NAME:-"/ndn/keys/ucla.edu"}
KEY_PREFIX=${KEY_PREFIX:-"/ndn/keys/ucla.edu"}
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

while getopts "hsS" flag; do
    case "$flag" in
	s) 
            echo Creating repo slice
            ccnsyncslice create "$SYNC_TOPO_PREFIX" "$SYNC_NAME_PREFIX"
            RET=$?
            echo "Status of ccnsyncslice create: $RET"
            exit 0
            ;;
	S)
	    pubkeys=`ls certs/*.pem`
	    cat <<EOF
Affiliation: $AFFI
Prefix of the signing key: $SIGNING_KEY_NAME
Prefix under which user keys will be published: $KEY_PREFIX

The following public keys will be signed: $pubkeys

EOF

	    while true; do
		read -p "Sign and publish user public keys with above parameters (yes|no)? " yn
		case $yn in
		    [Yy][eE][sS] ) 
			for cert in `ls ${CERTS}/*.pem 2>/dev/null`; do
			    USER=`basename $cert .pem`
			    $MKEY -i $USER -a $AFFI -f $cert -F $KEYSTORE -P $SIGNING_KEY_NAME -p ${KEY_PREFIX}/${USER} -x $VALID_DAYS && echo "Signed $USER"
			done
			exit 0

			;;
		    [Nn][oO] ) 
			exit 1
			;;
		    * ) 
			echo "Please answer yes or no."
			;;
		esac
	    done
	    ;;
        *)
	    usage
	    ;;
    esac
done

usage
