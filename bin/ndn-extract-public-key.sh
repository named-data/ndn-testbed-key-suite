#!/bin/bash

function usage {
    cat <<EOF
    $0 [-h] (-D | -i ccnx_keystore_file) [-o output_file]
      -i specify input keystore file
      -D use default keystore file ($HOME/.ccnx/.ccnx_keystore)
      -o specify output file (stdout by default)

      Keystore password can be defined through CCNX_KEYSTORE_PASSWORD environment variable,
      if not explicitly defined, the default CCNx keystore password will be used
EOF
  exit 1
}

while getopts "hDi:o:" flag; do
    case "$flag" in
        i)
            INPUT=$OPTARG
            ;;
        o)
            OUTPUT=$OPTARG
            ;;
        D)
            INPUT="$HOME/.ccnx/.ccnx_keystore"
            ;;
        *)
            usage
            ;;
    esac
done

if [ "x$INPUT" == "x" ]; then
    usage
fi

if [ ! -f $INPUT ]; then
    echo "Keystore file [$INPUT] does not exist or you don't have enough permissions to read it"
    exit 1
fi

export KEY_PASSWORD=${CCNX_KEYSTORE_PASSWORD:-"Th1s1sn0t8g00dp8ssw0rd."}

echo "Extracting public key from private key [$INPUT] to [$OUTPUT]"

if [ "x$OUTPUT" == "x" ]; then
    openssl pkcs12 -in "$INPUT" -password env:KEY_PASSWORD -clcerts -nokeys -nomacver | openssl x509
else
    openssl pkcs12 -in "$INPUT" -password env:KEY_PASSWORD -clcerts -nokeys -nomacver | openssl x509 > $OUTPUT
fi
