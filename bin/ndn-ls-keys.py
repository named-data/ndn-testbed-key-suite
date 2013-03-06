#!/usr/bin/env python
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

try:
    import pyccn
except:
    print "ERROR: PyCCN is not found"
    print "   You can download and install it from here https://github.com/named-data/PyCCN"
    print "   If you're using OSX and macports, you can follow instructions http://irl.cs.ucla.edu/autoconf/client.html"
    exit(1)

NDN_rootKeySha256 = "\xA7\xD9\x8B\x81\xDE\x13\xFCV\xC5\xA6\x92\xB4D\x93nVp\x9DRop\xED9\xEF\xB5\xE2\x03\x29\xA5S\x3Eh"
NDN_root = str(pyccn.Name ("/ndn/keys/").append ("\xC1.M.K\x00" + NDN_rootKeySha256).append ("\xFD\x01\x00P\x81\xBB\x3D").append("\x00"))

import argparse

parser = argparse.ArgumentParser(description='Browse and verify correctness of published keys')
parser.add_argument('namespace', metavar='NDN-prefix', type=str, nargs='?',
                    help='''Key namespace or key name (e.g., /ndn/keys)''')
parser.add_argument('-q', '--quiet', dest='verbose', action='store_false', default=True,
                    help='''Quiet mode (verify keys without printing out certification chains)''')
parser.add_argument('-n', '--no-verify', dest='verify', action='store_false', default=True,
                    help='''Disable key verification (only enumerate)''')
parser.add_argument('-s', '--scope', dest='scope', action='store', type=int, default=None,
                    help='''Set scope for enumeration and verification (default no scope)''')
parser.add_argument('-t', '--timeout', dest='timeout', action='store', type=float, default=0.1,
                    help='''Maximum timeout for each fetching operation/Interest lifetime (default: 0.1s)''')
parser.add_argument('-M', '--no-meta', dest='check_meta', action='store_false', default=True,
                    help='''Disable checking meta data (e.g., certificate expiration)''')

from ndn_keys import verify

if __name__ == '__main__':
    args = parser.parse_args()
    if not args.namespace:
        parser.print_help ()
        exit (1)

    kv = verify.key_verifier (args)

    print "Enumerating all the keys (may take a couple of minutes)"
    keys = kv.enumerateKeysFromNamespace (pyccn.Name (args.namespace))

    if args.verify:
        print "\nVerifying keys from [%s%s%s] namespace:" % (verify.bcolors.OKBLUE, args.namespace, verify.bcolors.ENDC)
    else:
        print "\nAvailable keys in [%s%s%s] namespace:" % (verify.bcolors.OKBLUE, args.namespace, verify.bcolors.ENDC)

    for keyname in sorted (keys):
        print keyname

        if args.verify:
            verified = kv.verify (keyname)
            print "    %s" % (verify.bcolors.OKGREEN +"OK"+verify.bcolors.ENDC if verified else verify.bcolors.FAIL + "FAIL" + verify.bcolors.ENDC)
            print ""
