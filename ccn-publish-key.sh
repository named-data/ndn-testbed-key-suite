#!/bin/sh

OPENSSL=openssl
HEXDUMP=hexdump
BASEPREFIX=

SYNC_TOPO_PREFIX="/ndn/broadcast/sync/keys"
SYNC_NAME_PREFIX="/ndn/keys"

ccnsyncslice create "$SYNC_TOPO_PREFIX" "$SYNC_NAME_PREFIX"

export PATH="$BASEPREFIX/bin:$PATH"

function usage {
  if [ "x$1" != "x" ]; then
    echo $1 >&2
  fi
  cat <<EOF
    $0 [-h] [-i identity] [-a affiliation] [-f key_file]
	[-k signing_key] [-u pubkey_uri] [-p key_prefix] [-x validity_period]
	Reads key, storing it to local repo

	-h print this help message
	-i specify the real-world identity of the key owner
	-a specify the affiliation of the key owner
	-f specify the public key file
	-p specify the key name prefix

	-F specify the path to the keystore (directory that contains .ccnx_keystore file).
           Keystore password can be defined through CCNX_KEYSTORE_PASSWORD environment variable
	-P specify the name prefix of signing public key
	-x specify the validity period in days
EOF

  exit 1
}

while getopts "hi:a:f:p:F:P:x:" flag; do
    case "$flag" in
	i) IDENTITY=$OPTARG ;;
	a) AFFILIATION=$OPTARG ;;
	f) KEYFILE=$OPTARG ;;
	p) PREFIX=$OPTARG ;;

	F) SIGNKEY=$OPTARG ;;
        P) SIGNKEYURI=$OPTARG ;;
	x) FRESHNESS=$OPTARG ;;

	h | ?)
	    usage
	    ;;
    esac
done

if [ "x$IDENTITY" == "x" -o "x$AFFILIATION" == "x" -o \
     "x$KEYFILE" == "x"  -o "x$PREFIX" == "x" -o \
     "x$SIGNKEY" == "x"  -o "x$SIGNKEYURI" == "x" -o \
     "x$FRESHNESS" == "x" ]; then
    usage "Incorrect parameter usage"
fi 

# echo "x$IDENTITY" == "x" -o "x$AFFILIATION" == "x" -o "x$KEYFILE" == "x" -o "x$PREFIX" == "x" -o "x$SIGNKEY" == "x" -o "x$FRESHNESS" == "x"

if [ ! -f "$KEYFILE" ]; then
    echo "Cannot open key file [$KEYFILE]" >&2
    exit 1
fi

if [ ! -d "$SIGNKEY" ]; then
    echo "-F should specify directory where .ccnx_keystore file is located" >&2
    exit 1
fi

pubkey_base64=`$OPENSSL x509 -in "$KEYFILE" -pubkey -noout | $OPENSSL pkey -pubin -outform der | $OPENSSL dgst -sha1 -binary | base64`
pubkey_binhash=`echo $pubkey_base64 | base64 -D | $HEXDUMP -e '1/1 "^%02x"' | sed -e 's/\^/\%/g'`

valid_to=$(( `date -u +%s` + $FRESHNESS*24*3600 ))

info_base64=`echo "<Meta><Name>$IDENTITY</Name><Affiliation>$AFFILIATION</Affiliation><Valid_to>$valid_to</Valid_to></Meta>" | base64`

function repo_write {
   URL=$1
   BASE64_CONTENT=$2

   # Request interest from repo
   repo_command="$URL/%C1.R.sw/`openssl rand -hex 20 2>/dev/null`"
   ccnpeek -w 3 -s 1 "$repo_command" > /dev/null
   RET=$?
   if [ ! $RET -eq 0 ]; then
       echo "ERROR: Wrong URI or repo is not responding" >&2
       exit 1
   fi

   echo $BASE64_CONTENT | base64 -D | CCNX_DIR=$SIGNKEY ccnpoke -f -x 60 -t KEY -l -k "$SIGNKEYURI" "$URL/%00" 
}

repo_write "$PREFIX/$pubkey_binhash" $pubkey_base64
repo_write "$PREFIX/info/$pubkey_binhash" $info_base64

exit 0
