## Prerequisites

### 1. Add '/ndn/keys' route to your neighboring testbed nodes

You need to be able to send interests with '/ndn/keys' prefix to your neighbors to fetch key objects

This can be done by adding routes in your ccnd.conf to all neigbors, e.g.

	add /ndn/keys udp 10.0.XX.XX
        add /ndn/keys udp 10.0.YY.YY
        ...
        add /ndn/keys udp 10.0.ZZ.ZZ

Also, /ndn/keys needs to be added to ``CCND_AUTOREG`` variable to automatically register /ndn/keys prefix for every new face.

### 2. Run the repo if you are not yet running it

Decide which directory you want the repo to store its file,

	CCNR_DIRECTORY=/directory/to/store/repo/ ccnr &

## Key publishing

###  1. Create `site-config.sh` file and configure `AFFI`, `KEY_PREFIX` and `VALID_DAYS` `sign.sh` variables

- **`AFFI`** is affiliation that will be recorded in the info record (name will be inferred from the filename of the user's key). For more info, refer to [Deploying Key Management on NDN Testbed technical report](http://www.named-data.net/techreport/TR009-publishkey.pdf).

- **`KEY_PREFIX`** key prefix for your site.  For example, in UCLA, the key prefix is `/ndn/keys/ucla.edu`. Users' key will be published in the form `<KEY_PREFIX>/<username>/<key-hash>`.

- **`VALID_DAYS`** number of days the certification should be valid.  For example, you can set this value to 365.

### 2. Decide which keystore to use as your site keystore

For example, you can use

	ccninitkeystore ./site-keystore

to generate a new private/public key pair and put it in `site-keystore/.ccnx_keystore`

If you would like to use an existing private/public key pair, either copy it in `site-keystore/` folder, or modify `KEYSTORE` variable in ./sign.sh script.

If you would like to change default password, you can set and export `CCNX_KEYSTORE_PASSWORD` variable before executing `ccninitkeystore`.

### 3. Extract public key from the site's key and send it to CSU operator for signing

For example, you can issue the following command:

	bin/ndn-extract-public-key.sh -i site-keystore/.ccnx_keystore -o my-site.pem

And then email my-site.pem file to NDN root key operator (<root-key-admin@named-data.net>)

### 4. Put collected user public keys (`*.pem` files) in `certs/` folder

Name of the file will define which prefix will be used to publish a key. For example, if public key is stored in `certs/alex.pem` and `KEY_PREFIX` variable in `sign.sh` is set to `/ndn/keys/ucla.edu`, then this key will be published under prefix `/ndn/keys/ucla.edu/alex`.

### 5. Run signing script

Should be run *only once*.  Create a sync slice:

	./sign.sh -s

Sign keys in certs/ folder:

	./sign.sh -S

## Verify that publishing and sync succeeded

### Check repo

You can directly check contents of your repo by issuing the following command:

        ccnnamelist <path-to-the-repo>/repoFile1 | grep %C1.M.K | sort

If you don't see just published keys or if you don't see other published keys, please send contact root key operator.

### Check visible keys and signature paths

If you have PyCCN installed (http://github.com/named-data/PyCCN), you can run the following script that will enumerate all reachable keys and verify correctness of the signatures:

        ./bin/ndn-ls-keys.py /ndn/keys/<site's-name>

or

        ./bin/ndn-ls-keys.py /ndn/keys

For more options, refer to `./bin/ndn-ls-keys.py -h`
