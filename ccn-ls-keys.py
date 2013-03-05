#!/usr/bin/env python
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

try:
    import pyccn
except:
    print "ERROR: PyCCN is not found"
    print "   You can download and install it from here https://github.com/named-data/PyCCN"
    print "   If you're using OSX and macports, you can follow instructions http://irl.cs.ucla.edu/autoconf/client.html"

NDN_root = "/ndn/keys/%C1.M.K%00%A7%D9%8B%81%DE%13%FCV%C5%A6%92%B4D%93nVp%9DRop%ED9%EF%B5%E2%03%29%A5S%3Eh/%FD%01%00P%81%BB%3D/%00"



import argparse

parser = argparse.ArgumentParser(description='Browse and verify correctness of published keys')
parser.add_argument('namespace', metavar='NDN-prefix', type=str, nargs='?',
                    help='Key namespace or key name (e.g., /ndn/keys)')
parser.add_argument('-n', '--no-verify', dest='verify', action='store_false', default=True,
                    help='''Disable key verification (only enumerate)''')

args = parser.parse_args()
if not args.namespace:
    print parser.print_help ()
    exit (1)

ccn = pyccn.CCN ()

keys = {}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

def enumRecurs (name):
    import sys
    sys.stdout.write('.')
    sys.stdout.flush()
    # print ">> %s" % name
    base_len = len (name)
    excludeList = []
    while True:
        interestName = pyccn.Name (name)
        exclude1 = pyccn.ExclusionFilter ()
        # print "Exclude list: [%s]" % ",".join ([str(pyccn.Name().append (n)) for n in excludeList])
        exclude1.add_names ([pyccn.Name().append (n) for n in excludeList])
        interest_tmpl = pyccn.Interest (exclude = exclude1, interestLifetime=0.1, minSuffixComponents=1, maxSuffixComponents=100, scope=None)

        if True:
            class Slurp(pyccn.Closure):
                def __init__(self):
                    self.finished = False
                    self.done = False

                def upcall(self, kind, upcallInfo):
                    if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
                        co = upcallInfo.ContentObject
                        self.name = co.name
                        # print co.name
                        if len (co.name) == base_len:
                            self.done = True
                        else:
                            excludeList.append (co.name[base_len])
                    elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
                        self.done = True

                    self.finished = True
                    return pyccn.RESULT_OK

            slurp = Slurp ()
            ccn.expressInterest(interestName, slurp, interest_tmpl)
            while not slurp.finished:
                # print slurp.finished
                ccn.run (1)

            if slurp.done:
                break

            # recursive step
            higherName = slurp.name[base_len]
            # print higherName
            newName = pyccn.Name (interestName).append (higherName)
            enumRecurs (newName)

            if len(slurp.name) == (base_len+1) and len (slurp.name) > 3:
                # print slurp.name[base_len-2]
                if slurp.name [base_len-2][0:5] == '\xc1.M.K' and slurp.name [base_len-3] != "info":
                    keyname = slurp.name[0:(base_len-1)]
                    version = slurp.name[base_len-1]
                    # if not keys[str(keyname)] or keys[str(keyname)] < version:
                    #     keys[str(keyname)] = version
                    try:
                        # print "%s, %d" % (version, pyccn.Name.seg2num (version))

                        if keys[str(keyname)][2] <= pyccn.Name.seg2num (version):
                            keys[str(keyname)] = [version, False, pyccn.Name.seg2num (version)]
                    except:
                        keys[str(keyname)] = [version, False, pyccn.Name.seg2num (version)]

print "Enumerating all the keys (may take a couple of minutes)"
enumRecurs (pyccn.Name (args.namespace))

verified = { }

print "\nTrying to verify keys"

def authorizeKey (dataName, keyName):
    if len(keyName) < 1:
        return { "authorized":False, "formattedName":"%s%s: %s%s" % (bcolors.FAIL,"Invalid key name", str(keyName), bcolors.ENDC)}

    if len(dataName) <= len(keyName)-1:
        return { "authorized":False, "formattedName":"%s%s: %s%s" % (bcolors.FAIL,"Invalid key name", str(keyName), bcolors.ENDC)}

    keyBase = str(keyName[0:len(keyName)-1])
    dataBase = str(dataName[0:len(keyName)-1])
    if keyBase == dataBase:
        return { "authorized":True, "formattedName":"%s[AUTH KEY]%s %s%s%s%s" % (bcolors.OKBLUE, bcolors.ENDC, bcolors.OKGREEN, keyBase, bcolors.ENDC, str(pyccn.Name ().append (dataName[len(keyName)]))) }
    else:
        return { "authorized":False, "formattedName":"%s[WRONG KEY] %s%s%s" % (bcolors.FAIL, keyBase, bcolors.ENDC, str(pyccn.Name ().append (dataName[len(keyName)]))) }

def verify(name, spaces):
    class Slurp(pyccn.Closure):
        def __init__(self):
            self.finished = False
            self.verified = False

        def upcall(self, kind, upcallInfo):
            if kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
                return pyccn.RESULT_VERIFY

            if kind == pyccn.UPCALL_CONTENT:
                self.verified = True
                self.co = upcallInfo.ContentObject

            self.finished = True
            return pyccn.RESULT_OK

    slurp = Slurp ()
    ccn.expressInterest (name, slurp, pyccn.Interest (interestLifetime=0.1, childSelector=1, minSuffixComponents=1, maxSuffixComponents=20, scope=None))

    maxwait = 500
    while not slurp.finished and maxwait > 0:
        # print slurp.finished
        ccn.run (1)
        maxwait = maxwait - 1

    if not slurp.verified:
        print "%s%sCannot verify ContentObject%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
        # done at this point
        return False

    keyLocator = slurp.co.signedInfo.keyLocator
    if keyLocator:
        if keyLocator.keyName:
            auth = authorizeKey (slurp.co.name, keyLocator.keyName)
            print "%s|" % spaces
            print "%s+-> %s" % (spaces, auth["formattedName"])
            if not auth["authorized"]:
                return False

            return verify(keyLocator.keyName, "%s    " % spaces)
        else:
            if str(slurp.co.name) == NDN_root:
                print "%s|" % spaces
                print "%s--> self-signed NDN root" % spaces
                return True
            else:
                print "%s|" % spaces
                print "%s--> self-signed" % spaces
                return False
    else:
        print "%s Key locator missing"


for key in sorted (keys.keys ()):
    # keyname = pyccn.Name (key).append (keys[key][0])
    keyname = pyccn.Name (key)
    print keyname
    verified = verify (keyname, "    ")
    print "    %s" % ("OK" if verified else bcolors.FAIL + "FAIL" + bcolors.ENDC)
    print ""

