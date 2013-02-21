#!/bin/bash

D=`dirname "$0"`

MKEY=$D/mkey/ccn-publish-key.sh
KEYSTORE=$D/site-keystore/
AFFI=${AFFI:-"University of California, Los Angeles"}
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

                            read -p "Sign $cert (yes|no) [yes]: " yn
                            if [ "x$yn" == "xno" -o "x$yn" == "NO" -o "x$yn" == "nO" -o "x$yn" == "No" ]; then
                                continue
                            fi

                            read -p "Enter key name [${KEY_PREFIX}/${USER}]: " keyname
                            if [ "x$keyname" == "x" ]; then
                                keyname=${KEY_PREFIX}/${USER}
                            fi

                            while true; do
                                read -p "Enter real world identity of the signed key (full name): " real_identity
                                if [ "x$real_identity" == "x" ]; then
                                    echo "ERROR: you must specify real world identity for the signed key"
                                else
			            $MKEY -i "$real_identity" -a "$AFFI" -f "$cert" -F "$KEYSTORE" -P "$SIGNING_KEY_NAME" -p "$keyname" -x "$VALID_DAYS" && echo "Signed $USER"
                                    break
                                fi
                            done
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
