#!/bin/bash

OPENSSL=openssl
HEXDUMP=hexdump
if [ `uname` == "Linux" ]; then
    BASE64="base64 -i"
else
    BASE64="base64"
fi
SED=sed
XXD=xxd

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

if [ ! -f "$KEYFILE" ]; then
    echo "Cannot open key file [$KEYFILE]" >&2
    exit 1
fi

if [ ! -d "$SIGNKEY" ]; then
    echo "-F should specify directory where .ccnx_keystore file is located" >&2
    exit 1
fi

pubkey_base64=`$OPENSSL x509 -in "$KEYFILE" -pubkey -noout | $OPENSSL rsa -pubin -pubout -inform PEM -outform DER 2> /dev/null | $BASE64`
pubkey_binhash=`echo $pubkey_base64 | $BASE64 --decode | $OPENSSL dgst -sha256 -binary | $HEXDUMP -v -e '1/1 "^%02x"' | sed -e 's/\^/\%/g'`

valid_to=$(( `date -u +%s` + $FRESHNESS*24*3600 ))

info_base64=`echo "<Meta><Name>$IDENTITY</Name><Affiliation>$AFFILIATION</Affiliation><Valid_to>$valid_to</Valid_to></Meta>" | $BASE64`

export KEY_PASSWORD=${CCNX_KEYSTORE_PASSWORD:-"Th1s1sn0t8g00dp8ssw0rd."}
root_base64=`$OPENSSL pkcs12 -in "$SIGNKEY/.ccnx_keystore" -nomacver -password env:KEY_PASSWORD -clcerts -nokeys | $OPENSSL x509 -pubkey -noout | $OPENSSL rsa -pubin -pubout -inform PEM -outform DER 2> /dev/null | $BASE64`
root_binhash=`echo $root_base64 | $BASE64 --decode | $OPENSSL dgst -sha256 -binary | $HEXDUMP -v -e '1/1 "^%02x"' | sed -e 's/\^/\%/g'`

function repo_write {
   URL=$1
   BASE64_CONTENT=$2

   # Request interest from repo
   repo_command="$URL/%C1.R.sw/`openssl rand -hex 20 2>/dev/null`"
   ccnpeek -w 2 -s 1 "$repo_command" > /dev/null
   RET=$?
   if [ ! $RET -eq 0 ]; then
       echo "ERROR: Wrong URI or repo is not responding" >&2
       exit 1
   fi

   if [ "$SIGNKEYURI" == "self" ]; then
       echo "Writing self-certified key"
       echo $BASE64_CONTENT | $BASE64 --decode | CCNX_DIR=$SIGNKEY ccnpoke -w 2 -x 2000 -t KEY -l "$URL/%00" 
   else
       # echo "Writing site-certified key"
       echo $BASE64_CONTENT | $BASE64 --decode | CCNX_DIR=$SIGNKEY ccnpoke -w 2 -x 2000 -t KEY -l -k "$SIGNKEYURI/%C1.M.K%00$root_binhash" "$URL/%00" 
   fi
}

TIME=`date -u +%s`
VERSION=`printf "%.10x" $TIME | $XXD -r -p | $HEXDUMP -v -e '1/1 "^%02x"' | $SED -e 's/\^/\%/g'`

repo_write "$PREFIX/%C1.M.K%00$pubkey_binhash/%FD%01$VERSION" "$pubkey_base64"
repo_write "$PREFIX/info/%C1.M.K%00$pubkey_binhash/%FD%01$VERSION" "$info_base64"

exit 0
