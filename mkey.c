#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <ccn/sync.h>
#include <libxml/parser.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#ifdef __APPLE__
#include <openssl/sha.h>
#endif

#define SYNC_TOPO_PREFIX "/KEYS"
#define SYNC_NAME_PREFIX "/ndn/keys"

static void
usage(const char *progname)
{
  fprintf(stderr,
      "%s [-h] [-c configure_file] [-i identity] [-a affiliation] [-f key_file]\n"
      "    [-k signing_key] [-u pubkey_uri] [-p key_prefix] [-x validity_period]\n"
      "    Reads key, storing it to local repo.\n"
      "    -h print this help message.\n"
      "    -c specify the configuration file.\n"
      "    -i specify the real-world identity of the key owner.\n"
      "    -a specify the affiliation of the key owner.\n"
      "    -f specify the public key file.\n"
      "    -k specify the path of keystore.\n"
      "    -u specify the name prefix of signing public key.\n"
      "    -p specify the key name prefix.\n"
      "    -x specify the validity period in days.\n",
      progname);
  exit(1);
}

static void
base64(const char *input, int input_size, char **output)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, input_size);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buf = (char *)malloc(bptr->length);
  memcpy(buf, bptr->data, bptr->length - 1);
  buf[bptr->length - 1] = '\0';
  *output = buf;

  BIO_free_all(b64);
}

static void
unbase64(const char *input, int input_size, char **output, int *output_size)
{
  BIO *b64, *bmem;

  char *buf = (char*) calloc(1, sizeof(char) * input_size);

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf((void*) input, input_size);
  bmem = BIO_push(b64, bmem);
  
  *output_size = BIO_read(bmem, buf, input_size);
  *output = buf;

  BIO_free_all(bmem);
}

static void
hash(const char *digest_name, unsigned char *input, size_t input_size, unsigned char *output, size_t *len)
{
  EVP_MD_CTX mdctx;
  const EVP_MD *md;

  md = EVP_get_digestbyname(digest_name);
  if (!md)
  {
    fprintf(stderr, "Unknown digest name %s\n", digest_name);
    exit(1);
  }

  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, input, input_size);
  EVP_DigestFinal_ex(&mdctx, output, len);
  EVP_MD_CTX_cleanup(&mdctx);
}

static void
trim(char **pstring)
{
  char *string = *pstring;
  char *trimmed;
  int i = 0, j = strlen(string);

  for (; i < j; i++)
    if (!isspace(string[i]))
      break;

  j--;
  for (; j >= i; j--)
    if (!isspace(string[j]))
      break;

  trimmed = calloc(1, sizeof(char) * (j - i + 2));
  strncpy(trimmed, &string[i], j - i + 1);
  free(string);
  *pstring = trimmed;
}

static void
extract_config(const xmlDocPtr doc, char **affl, char **prefix, char **signkey, char **keyuri, int *fresh)
{
  xmlNodePtr cur = xmlDocGetRootElement(doc);

  if (cur == NULL)
  {
    fprintf(stderr, "Empty configuration file\n");
    exit(1);
  }

  if (xmlStrcmp(cur->name, (const xmlChar *) "config"))
  {
    fprintf(stderr, "Wrong configuration file, root node != config\n");
    exit(1);
  }

  for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
  {
    if (!xmlStrcmp(cur->name, (const xmlChar *) "affiliation"))
    {
      if (*affl == NULL)
      {
        *affl = (char*) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
        trim(affl);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "prefix"))
    {
      if (*prefix == NULL)
      {
        *prefix = (char*) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
        trim(prefix);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "signing_key"))
    {
      if (*signkey == NULL)
      {
        *signkey = (char*) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
        trim(signkey);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "pubkey_uri"))
    {
      if (*keyuri == NULL)
      {
        *keyuri = (char*) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
        trim(keyuri);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "validity_period"))
    {
      if (*fresh == 0)
      {
        xmlChar *tmp = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
        *fresh = atoi((char*) tmp);
        xmlFree(tmp);
      }
    }
  }
}

static void
create_slice(struct ccn *h, char *topo, char *prefix)
{
  int res = 0;
  struct ccns_slice *sync = ccns_slice_create();

  struct ccn_charbuf *t = ccn_charbuf_create();
  res |= ccn_name_from_uri(t, topo);
  struct ccn_charbuf *p = ccn_charbuf_create();
  res |= ccn_name_from_uri(p, prefix);

  if (res < 0)
  {
    fprintf(stderr, "Invalid topo or/and prefix\n");
    exit(1);
  }
  
  res = ccns_slice_set_topo_prefix(sync, t, p);

  struct ccn_charbuf *name = ccn_charbuf_create();
  ccns_slice_name(name, sync);

  struct ccns_slice *tmp = ccns_slice_create();
  if (ccns_read_slice(h, name, tmp) != 0)
  {
    res |= ccns_write_slice(h, sync, name);
    if (res != 0)
    {
      fprintf(stderr, "Create slice failed.\n");
      exit(1);
    }
  }

  ccn_charbuf_destroy(&t);
  ccn_charbuf_destroy(&p);
  ccn_charbuf_destroy(&name);
  ccns_slice_destroy(&tmp);
  ccns_slice_destroy(&sync);
}

int
main(int argc, char **argv)
{
  const char *progname = argv[0];
  struct ccn *ccn = NULL;
  int res = 0;
  char *identity = NULL;
  char *affiliation = NULL;
  char *keyfile = NULL;
  char *signkey = NULL;
  char *config = NULL;
  char *prefix = NULL;
  char *keyuri = NULL;
  int freshness = 0;
  xmlDocPtr doc = NULL;
  
  while ((res = getopt(argc, argv, "hc:i:f:a:x:k:u:p:")) != -1)
    switch (res)
    {
      case 'i':
        identity = strdup(optarg);
        break;
      case 'a':
        affiliation = strdup(optarg);
        break;
      case 'f':
        keyfile = strdup(optarg);
        break;
      case 'k':
        signkey = strdup(optarg);
        break;
      case 'c':
        config = strdup(optarg);
        break;
      case 'p':
        prefix = strdup(optarg);
        break;
      case 'u':
        keyuri = strdup(optarg);
        break;
      case 'x':
        freshness = atoi(optarg);
        break;
      case 'h':
      default:
        usage(progname);
        break;
    }

  argc -= optind;
  argv += optind;
  if (argc != 0)
    usage(progname);

  LIBXML_TEST_VERSION

  if (config != NULL)
  {
    doc = xmlReadFile(config, NULL, 0);
    if (doc == NULL)
    {
      fprintf(stderr, "Failed to parse the configuration file %s\n", config);
      exit(1);
    }
    else
      extract_config(doc, &affiliation, &prefix, &signkey, &keyuri, &freshness);
  }

  if (affiliation == NULL)
  {
    fprintf(stderr, "No affiliation specified.\n");
    exit(1);
  }
  if (prefix == NULL)
  {
    fprintf(stderr, "No prefix provided.\n");
    exit(1);
  }
  if (signkey == NULL)
  {
    fprintf(stderr, "No keystore provided.\n");
    exit(1);
  }
  if (keyuri == NULL)
  {
    fprintf(stderr, "No key uri provided.\n");
    exit(1);
  }
  if (keyfile == NULL)
  {
    fprintf(stderr, "No public keyfile provided.\n");
    exit(1);
  }
  if (freshness == 0)
  {
    fprintf(stderr, "No validity period provided.\n");
    exit(1);
  }

  FILE *fp = fopen(keyfile, "r");
  if (fp == NULL)
  {
    fprintf(stderr, "Cannot open key file.\n");
    exit(1);
  }

  OpenSSL_add_all_digests();

  unsigned char *keydata = NULL;
  size_t kd_size, len;
  char *keyhash, *encodedhash;
  X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
  fclose(fp);
  kd_size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &keydata);
  if (kd_size < 0)
  {
    fprintf(stderr, "Invalid cert\n");
    exit(1);
  }

  keyhash = calloc(1, sizeof(char) * (SHA_DIGEST_LENGTH + 1));
#ifdef __APPLE__
  SHA1(keydata, kd_size, (unsigned char *)keyhash);
  len = SHA_DIGEST_LENGTH;
#else
  hash("SHA1", keydata, kd_size, (unsigned char*) keyhash, &len);
#endif
  base64(keyhash, len, &encodedhash);
  char *pos = strchr(encodedhash, '/');
  while (pos != NULL)
  {
    *pos = '-';
    pos = strchr(pos, '/');
  }
  free(keyhash);

  struct ccn_charbuf *keyname = ccn_charbuf_create();
  char *pname = calloc(1, sizeof(char) * 100);
  sprintf(pname, "%s/%s", prefix, encodedhash);
  ccn_name_from_uri(keyname, pname);

  ccn = ccn_create();
  if (ccn_connect(ccn, NULL) == -1)
  {
    fprintf(stderr, "Could not connect to ccnd\n");
    exit(1);
  }

  create_slice(ccn, SYNC_TOPO_PREFIX, SYNC_NAME_PREFIX);

  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  sp.type = CCN_CONTENT_KEY;
  sp.template_ccnb = ccn_charbuf_create();
  ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_SignedInfo, CCN_DTAG);
  ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, "%d", freshness);
  sp.sp_flags |= CCN_SP_TEMPL_FRESHNESS;

  struct ccn_keystore *keystore = ccn_keystore_create();
  res = ccn_keystore_init(keystore, signkey, "Th1s1sn0t8g00dp8ssw0rd.");
  if (res != 0)
  {
    fprintf(stderr, "Failed to initialize keystore.\n");
    exit(1);
  }
  const struct ccn_pkey *pkey = ccn_keystore_public_key(keystore);
  char *signkeyhash = calloc(1, sizeof(char) * (SHA_DIGEST_LENGTH + 1));
  char *encoded = NULL;
  size_t signkey_size = i2d_PUBKEY((EVP_PKEY*) pkey, NULL);
  unsigned char *signkey_data = NULL;
  size_t hash_size;

  i2d_PUBKEY((EVP_PKEY*) pkey, &signkey_data);
#ifdef __APPLE__
  SHA1(signkey_data, signkey_size, (unsigned char *)signkeyhash);
  hash_size = SHA_DIGEST_LENGTH;
#else
  hash("SHA1", signkey_data, signkey_size,
      (unsigned char*) signkeyhash, &hash_size);
#endif
  base64(signkeyhash, hash_size, &encoded);
  pos = strchr(encoded, '/');
  while (pos != NULL)
  {
    *pos = '-';
    pos = strchr(pos, '/');
  }

  struct ccn_charbuf *c = ccn_charbuf_create();
  ccn_name_from_uri(c, keyuri);
  ccn_name_from_uri(c, encoded);
  ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_KeyLocator, CCN_DTAG);
  ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_KeyName, CCN_DTAG);
  ccn_charbuf_append(sp.template_ccnb, c->buf, c->length);
  ccn_charbuf_append_closer(sp.template_ccnb); // KeyName
  ccn_charbuf_append_closer(sp.template_ccnb); // KeyLocator
  sp.sp_flags |= CCN_SP_TEMPL_KEY_LOCATOR;
  ccn_charbuf_append_closer(sp.template_ccnb); // SignedInfo
  ccn_charbuf_destroy(&c);

  free(encoded);
  free(signkeyhash);
  ccn_keystore_destroy(&keystore);

  struct ccn_charbuf *default_pubid = ccn_charbuf_create();
  res = ccn_load_private_key(ccn, signkey, "Th1s1sn0t8g00dp8ssw0rd.", default_pubid);
  if (res != 0)
  {
    fprintf(stderr, "Invalid keystore.\n");
    exit(1);
  }
  memcpy(sp.pubid, default_pubid->buf, default_pubid->length);
  
  struct ccn_charbuf *name_v = ccn_charbuf_create();
  ccn_charbuf_append_charbuf(name_v, keyname);
  ccn_name_from_uri(name_v, "%C1.R.sw");
  ccn_name_append_nonce(name_v);
  struct ccn_charbuf *templ = ccn_charbuf_create();
  ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG);
  ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG);
  ccn_charbuf_append_closer(templ);
  ccnb_tagged_putf(templ, CCN_DTAG_Scope, "%d", 1);
  ccn_charbuf_append_closer(templ);
  res = ccn_get(ccn, name_v, NULL, 6000, NULL, NULL, NULL, 0);
  ccn_charbuf_destroy(&name_v);
  if (res < 0)
  {
    fprintf(stderr, "No response from repository\n");
    exit(1);
  }
  
  char *info = calloc(1, sizeof(char) * 100);
  sprintf(info, "<Meta><Name>%s</Name><Affiliation>%s</Affiliation></Meta>",
      identity, affiliation);
  struct ccn_charbuf *infoname = ccn_charbuf_create();
  ccn_name_from_uri(infoname, prefix);
  ccn_name_from_uri(infoname, "info");
	ccn_name_from_uri(infoname, encodedhash);

  struct ccn_charbuf *content = ccn_charbuf_create();
  ccn_name_append_numeric(keyname, CCN_MARKER_SEQNUM, 0);
  sp.sp_flags |= CCN_SP_FINAL_BLOCK;
  res = ccn_sign_content(ccn, content, keyname, &sp, keydata, kd_size);
  if (res != 0)
  {
    fprintf(stderr, "Failed to encode ContentObject (res == %d)\n", res);
    exit(1);
  }
  res = ccn_put(ccn, content->buf, content->length);
  if (res < 0)
  {
    fprintf(stderr, "ccn_put faild (res == %d)\n", res);
    exit(1);
  }
  
  name_v = ccn_charbuf_create();
  ccn_charbuf_append_charbuf(name_v, infoname);
  ccn_name_from_uri(name_v, "%C1.R.sw");
  ccn_name_append_nonce(name_v);
  res = ccn_get(ccn, name_v, templ, 6000, NULL, NULL, NULL, 0);
  ccn_charbuf_destroy(&templ);
  ccn_charbuf_destroy(&name_v);
  if (res < 0)
  {
    fprintf(stderr, "No response from repository\n");
    exit(1);
  }
  
  sp.type = CCN_CONTENT_DATA;
  ccn_name_append_numeric(infoname, CCN_MARKER_SEQNUM, 0);
  struct ccn_charbuf *meta = ccn_charbuf_create();
  ccn_sign_content(ccn, meta, infoname, &sp, info, strlen(info));
  ccn_put(ccn, meta->buf, meta->length);
  
  ccn_charbuf_destroy(&content);
  ccn_charbuf_destroy(&meta);
  ccn_charbuf_destroy(&infoname);
  ccn_charbuf_destroy(&keyname);
  ccn_charbuf_destroy(&sp.template_ccnb);
  ccn_destroy(&ccn);

  return 0;
}
