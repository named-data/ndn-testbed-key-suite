#!/usr/bin/env python
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

try:
    import pyccn
except:
    print "ERROR: PyCCN is not found"
    print "   You can download and install it from here https://github.com/named-data/PyCCN"
    print "   If you're using OSX and macports, you can follow instructions http://irl.cs.ucla.edu/autoconf/client.html"

ccn = pyccn.CCN ()

keys = {}

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
        interest_tmpl = pyccn.Interest (exclude = exclude1, interestLifetime=0.01, minSuffixComponents=1, maxSuffixComponents=100, scope=None)

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
                        if keys[str(keyname)][0] <= version:
                            keys[str(keyname)] = [version, False]
                    except:
                        keys[str(keyname)] = [version, False]


print "Get all keys first (including unverifiable ones)"
enumRecurs (pyccn.Name ("/ndn/keys"))

verified = { }

print "\nTrying to verify keys"

for key in sorted (keys.keys ()):
    class Slurp(pyccn.Closure):
        def __init__(self):
            self.finished = False
            self.verified = False

        def upcall(self, kind, upcallInfo):
            # if kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
            #     print "Asking to verify"
            #     return pyccn.RESULT_VERIFY

            if kind == pyccn.UPCALL_CONTENT:
                self.verified = True
                # return pyccn.RESULT_VERIFY

            self.finished = True
            return pyccn.RESULT_OK

    slurp = Slurp ()
    keyname = pyccn.Name (key).append (keys[key][0])
    ccn.expressInterest (keyname, slurp, pyccn.Interest (interestLifetime=0.01, minSuffixComponents=2, maxSuffixComponents=2, scope=None))

    while not slurp.finished:
        # print slurp.finished
        ccn.run (1)

    print "[%4s] %s" % ("OK" if slurp.verified else "FAIL", keyname)

    # print "Key: %s%s [%s]" % (key, str (pyccn.Name ().append (keys[key])), "OK" if keys[key][1] else "Not OK")
# print "Key: \n".join (keys)

