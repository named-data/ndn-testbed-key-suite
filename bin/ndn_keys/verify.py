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

class key_verifier:
    def __init__ (self, args):
        self.ccn = pyccn.CCN ()
        self.args = args
        self.m_keyCache = {}

    def enumerateKeysFromNamespace(self, name):
        keys = []
        if self.args.verbose:
            # print ">>> %s" % name
            import sys
            sys.stdout.write('.')
            sys.stdout.flush()

        base_len = len (name)
        excludeList = []
        while True:
            interestName = pyccn.Name (name)
            exclude1 = pyccn.ExclusionFilter ()
            exclude1.add_names ([pyccn.Name().append (n) for n in excludeList])
            interest_tmpl = pyccn.Interest (exclude = exclude1, interestLifetime=self.args.timeout, minSuffixComponents=1, maxSuffixComponents=100, scope=self.args.scope)

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
            self.ccn.expressInterest(interestName, slurp, interest_tmpl)
            while not slurp.finished:
                # print slurp.finished
                self.ccn.run (1)

            if slurp.done:
                # print "Done with %s" % interestName
                break

            keyFound = False
            if slurp.name [base_len][0:5] == '\xc1.M.K':
                if slurp.name [base_len-1] != "info":
                    # if it is not a real key, but just meta
                    keyname = slurp.name[0:base_len+1]
                    keys.append (pyccn.Name (keyname))

                keyFound = True

            if not keyFound:
                if len(slurp.name) == base_len+2 and slurp.name[base_len+1][0] == '\x00':
                    # skip legacy stuff
                    continue

                if len(slurp.name) == base_len+4 and slurp.name [base_len] == "info" and slurp.name[base_len+3][0] == '\x00':
                    # skip metadata
                    continue

                # recursive step
                higherName = slurp.name[base_len]
                newName = pyccn.Name (interestName).append (higherName)
                keys += self.enumerateKeysFromNamespace (newName)

        return keys

    def getLatestVersion(self, name):
        try:
            return self.m_keyCache[str(name)]
        except:
            pass

        base_len = len (name)
        excludeList = []
        version = 0
        co = None
        while True:
            interestName = pyccn.Name (name)
            exclude1 = pyccn.ExclusionFilter ()
            exclude1.add_names ([pyccn.Name().append (n) for n in excludeList])
            interest_tmpl = pyccn.Interest (exclude = exclude1, interestLifetime=self.args.timeout, minSuffixComponents=1, maxSuffixComponents=100, scope=self.args.scope)

            class Slurp(pyccn.Closure):
                def __init__(self):
                    self.finished = False
                    self.done = False

                def upcall(self, kind, upcallInfo):
                    if kind == pyccn.UPCALL_CONTENT or kind == pyccn.UPCALL_CONTENT_UNVERIFIED:
                        self.co = upcallInfo.ContentObject
                        if len (self.co.name) == base_len:
                            self.done = True
                        else:
                            excludeList.append (self.co.name[base_len])
                    elif kind == pyccn.UPCALL_INTEREST_TIMED_OUT:
                        self.done = True

                    self.finished = True
                    return pyccn.RESULT_OK

            slurp = Slurp ()
            self.ccn.expressInterest(interestName, slurp, interest_tmpl)
            while not slurp.finished:
                # print slurp.finished
                self.ccn.run (1)

            if slurp.done:
                # print "Done with %s" % interestName
                break

            try:
                newversion = pyccn.Name.seg2num (slurp.co.name [len(name)])
                if newversion > version:
                    version = newversion
                    co = slurp.co
            except:
                print "ERROR: Unversioned content object: %s" % interestName
                return None

        self.m_keyCache[str(name)] = co
        return co

    def authorizeKey (self, dataName, keyName):
        if len(keyName) < 1:
            return { "authorized":False, "formattedName":"%s%s: %s%s" % (bcolors.FAIL,"Invalid key name", str(keyName), bcolors.ENDC)}

        if len(dataName) <= len(keyName)-1:
            return { "authorized":False, "formattedName":"%s%s: %s%s" % (bcolors.FAIL,"Invalid key name", str(keyName), bcolors.ENDC)}

        keyBase = str(keyName[:-1])
        dataBase = str(dataName[0:len(keyName)-1])  # this has to be this way (it's keyName length, not dataName length)
        if keyBase == dataBase:
            return { "authorized":True,
                     "formattedName":"%s[AUTH KEY]%s %s%s%s%s" % (
                         bcolors.OKBLUE, bcolors.ENDC,
                         bcolors.OKGREEN, keyBase, bcolors.ENDC,
                         str(pyccn.Name ().append (keyName[-1]))
                         ) }
        else:
            return { "authorized":False,
                     "formattedName":"%s[WRONG KEY] %s%s%s" % (
                         bcolors.FAIL, keyBase, bcolors.ENDC,
                         str(pyccn.Name ().append (keyName[-1]))) }

    def getMetaInfo(self, name, key_digest, spaces):
        class KeyInfoClosure(pyccn.Closure):
            def __init__(self):
                self.co = None
                self.finished = False

            def upcall(self, kind, upcallInfo):
                if kind == pyccn.UPCALL_CONTENT_UNVERIFIED or kind == pyccn.UPCALL_CONTENT:
                    self.co = upcallInfo.ContentObject

                self.finished = True
                return pyccn.RESULT_OK

        closure = KeyInfoClosure ()
        info_name = pyccn.Name (name[:-3]).append ("info").append (name[-3]).append (name[-2]).append (name[-1])
        self.ccn.expressInterest (info_name, closure, pyccn.Interest (interestLifetime=self.args.timeout, scope=self.args.scope))

        while not closure.finished:
            self.ccn.run (1)

        if closure.co == None:
            if self.args.verbose:
                print "%s%s    [FAIL META] No META info for the key%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
            return None
            
        if closure.co.signedInfo.publisherPublicKeyDigest != key_digest:
            if self.args.verbose:
                print "%s%s    [FAIL META] PublisherPublicKeyDigest is invalid%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
            return None

        return closure.co

    def isValidMeta (self, metaCo, timestamp, spaces):
        import xml.etree.ElementTree as ET
        import time

        if metaCo is None:
            return False

        # check expiration
        root = ET.fromstring (metaCo.content)
        valid_to = -1

        for v in root.findall('Valid_to'):
            valid_to_temp = int(v.text)
            valid_to = valid_to_temp if (valid_to < 0 or valid_to > valid_to_temp) else valid_to

        now = time.time()

        if now < valid_to:
            if self.args.verbose:
                print "%s%s    [VALID META]%s ValidTo: %s%s%s" % (spaces, bcolors.OKBLUE, bcolors.ENDC, bcolors.OKGREEN, time.ctime(valid_to), bcolors.ENDC)
            return True
        else:
            if self.args.verbose:
                print "%s%s    [FAIL META] Certification expired (ValidTo: %s)%s" % (spaces, bcolors.FAIL, time.ctime(valid_to), bcolors.ENDC)
            return False

    def getVerifiedKey (self, keyname, spaces):
        latestVersion = self.getLatestVersion (keyname) # will cache, if necessary
        if not latestVersion:
            return None

        if self.args.check_meta:
            timestamp = latestVersion.signedInfo.timeStamp
            key_digest = latestVersion.signedInfo.publisherPublicKeyDigest

            meta = self.getMetaInfo (latestVersion.name, key_digest, spaces[4:])
            try:
                if not self.isValidMeta (meta, timestamp, spaces[4:]):
                    return None
            except:
                if self.args.verbose:
                    print "%s    %s!!! corrupt or missing META data !!!%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
                # i.e., corrupt meta
                return None

        keyLocator = latestVersion.signedInfo.keyLocator
        if keyLocator:
            if keyLocator.keyName and str(keyLocator.keyName) != str(keyname):
                auth = self.authorizeKey (latestVersion.name, keyLocator.keyName)
                if self.args.verbose:
                    print "%s|" % spaces
                    print "%s+-> %s" % (spaces, auth["formattedName"])

                if not auth["authorized"]:
                    return False

                keyObject = self.getVerifiedKey (keyLocator.keyName, "%s    " % spaces)
                if not keyObject:
                    if self.args.verbose:
                        print "%s    %s!!! key cannot be fetched or verified !!!%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
                    return False

                key = pyccn.Key ()
                key.fromDER (public = keyObject.content)

            elif keyLocator.keyName: # self-signed
                if str(latestVersion.name) == NDN_root:
                    if self.args.verbose:
                        print "%s|" % spaces
                    if latestVersion.signedInfo.publisherPublicKeyDigest == NDN_rootKeySha256:
                        if self.args.verbose:
                            print "%s--> %sself-signed NDN root%s" % (spaces, bcolors.OKGREEN, bcolors.ENDC)

                        key = pyccn.Key ()
                        key.fromDER (public = latestVersion.content)
                    else:
                        if self.args.verbose:
                            print "%s    %s!!! fake NDN root key !!!%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
                        return None
                else:
                    if self.args.verbose:
                        print "%s|" % spaces
                        print "%s--> %sinvalid self-signed trust anchor%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
                    return None

            else: # another way to self-sign
                if str(latestVersion.name) == NDN_root:
                    if self.args.verbose:
                        print "%s|" % spaces
                    if latestVersion.signedInfo.publisherPublicKeyDigest == NDN_rootKeySha256:
                        if self.args.verbose:
                            print "%s--> %sself-signed NDN root%s" % (spaces, bcolors.OKGREEN, bcolors.ENDC)

                        key = keyLocator.key
                    else:
                        if self.args.verbose:
                            print "%s    %s!!! fake NDN root key !!!%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
                        return None
                else:
                    if self.args.verbose:
                        print "%s|" % spaces
                        print "%s--> %sinvalid self-signed trust anchor%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
                    return None
        else:
            if self.args.verbose:
                print "%s Key locator missing"
            return None

        if latestVersion.verify_signature (key):
            if self.args.check_meta:
                if meta.verify_signature (key):
                    return latestVersion
                else:
                    if self.args.verbose:
                        print "%s--> %sinvalid signature for META data%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
                        return None
            else:
                return latestVersion
        else:
            if self.args.verbose:
                print "%s--> %sinvalid signature%s" % (spaces, bcolors.FAIL, bcolors.ENDC)
            return None

    def verify(self, name, spaces = "    "):
        verifiedKey = self.getVerifiedKey (name, spaces)
        if verifiedKey:
            return True
        else:
            return False

