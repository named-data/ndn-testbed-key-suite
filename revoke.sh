#!/usr/bin/env bash

D=`dirname "$0"`

if [ -f "$D/site-config.sh" ]; then
    source "$D/site-config.sh"
else
    echo "Please configure your site's parameters in [site-config.sh]"
    exit 1
fi

if [ "x$AFFI" == "x" ]; then
    echo "AFFI variable is not configured in [site-config.sh]"
    exit 1
fi

# the only difference between signing and revoking
VALID_DAYS=-1

if [ "x$KEY_PREFIX" == "x" ]; then
    echo "KEY_PREFIX variable is not configured in [site-config.sh]"
    exit 1
fi

SIGNING_KEY_NAME=${SIGNING_KEY_NAME:-"/ndn/keys/ucla.edu"}

MKEY=$D/bin/ndn-publish-key.sh
KEYSTORE=$D/site-keystore/
CERTS=$D/certs
REVOKED_CERTS=$D/revoked-certs

SYNC_TOPO_PREFIX="/ndn/broadcast/sync/keys"
SYNC_NAME_PREFIX="/ndn/keys"

function usage {
    cat <<EOF
Usage:
  $0 [-h] (-r)
      Revoke user public keys

      -h print this help message
      -r revoke and publish revocation of the public keys (*.pem) located in ${CERTS} folder
EOF
    exit 1
}

while getopts "hr" flag; do
    case "$flag" in
	r)
	    pubkeys=`ls certs/*.pem`
	    cat <<EOF
Affiliation: $AFFI
Prefix under which key revocations will be published: $KEY_PREFIX

The following public keys will be revoked: $pubkeys

EOF

	    while true; do
		read -p "Sign and publish revocation of user public keys with above parameters (yes|no)? " yn
		case $yn in
		    [Yy][eE][sS] )
			for cert in `ls ${CERTS}/*.pem 2>/dev/null`; do
                            USER=`basename $cert .pem`

                            read -p "Revoke $cert (yes|no) [yes]: " yn
                            if [ "x$yn" == "xno" -o "x$yn" == "NO" -o "x$yn" == "nO" -o "x$yn" == "No" ]; then
                                continue
                            fi

                            read -p "Enter key name [${KEY_PREFIX}/${USER}]: " keyname
                            if [ "x$keyname" == "x" ]; then
                                keyname=${KEY_PREFIX}/${USER}
                            fi

                            while true; do
                                read -p "Enter revocation reason: " real_identity
                                if [ "x$real_identity" == "x" ]; then
                                    echo "ERROR: you must specify revocation reason"
                                else
			            $MKEY -i "REVOKED: $real_identity" -a "$AFFI" -f "$cert" -F "$KEYSTORE" -P "$KEY_PREFIX" -p "$keyname" -x "$VALID_DAYS" && echo "Revoked $USER"
                                    mv "$cert" "${REVOKED_CERTS}/"
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
