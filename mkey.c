#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ccn/ccn.h>
#include <ccn/signing.h>
#include <ccn/uri.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

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
      "    -k specify the file containing signing private key.\n"
      "    -u specify the URI of signing public key.\n"
      "    -p specify the key name prefix.\n"
      "    -x specify the validity period in days.\n",
      progname);
  exit(1);
}

static void
base64(const char *input, char *output)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;
  char *buf;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, strlen(input));
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  output = (char *)malloc(bptr->length);
  memcpy(output, bptr->data, bptr->length - 1);
  output[bptr->length - 1] = '\0';

  BIO_free_all(b64);
}

static void
unbase64(const char *input, char *output)
{
  BIO *b64, *bmem;
  int len = strlen(input);

  output = (char *)malloc(len);
  memset(output, 0, len);

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf((void *)input, len);
  bmem = BIO_push(b64, bmem);
  
  BIO_read(bmem, output, len);

  BIO_free_all(bmem);
}

static void
hash(char *digest_name, char *input, char *output, int *len)
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
  EVP_DigestUpdate(&mdctx, input, strlen(input));
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
	*affl = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	trim(affl);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "prefix"))
    {
      if (*prefix == NULL)
      {
	*prefix = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	trim(prefix);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "signing_key"))
    {
      if (*signkey == NULL)
      {
	*signkey = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	trim(signkey);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "pubkey_uri"))
    {
      if (*keyuri == NULL)
      {
	*keyuri = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	trim(signkey);
      }
      continue;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "validity_period"))
    {
      if (*fresh == 0)
      {
	xmlChar *tmp = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	*fresh = atoi(tmp);
	xmlFree(tmp);
      }
    }
  }
}

int
main(int argc, char **argv)
{
  const char *progname = argv[0];
  struct ccn *ccn = NULL;
  int res;
  char *identity = NULL;
  char *affiliation = NULL;
  char *keyfile = NULL;
  char *signkey = NULL;
  char *config = NULL;
  char *prefix = NULL;
  char *keyuri = NULL;
  int freshness = 0;
  struct ccn_charbuf *name;
  xmlDocPtr doc = NULL;
  FILE *fp1, *fp2;
  
  while ((res = getopt(argc, argv, "hakxc:i:f:")) != -1)
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
    fprintf(stderr, "No signing key provided.\n");
    exit(1);
  }
  if (keyuri == NULL)
  {
    fprintf(stderr, "No key uri provided.\n");
    exit(1);
  }
  if (freshness == 0)
  {
    fprintf(stderr, "No validity period provided.\n");
    exit(1);
  }

  fp1 = fopen(keyfile, "r");
  if (fp1 == NULL)
  {
    fprintf(stderr, "Cannot open key file.\n");
    exit(1);
  }
  fp2 = fopen(signkey, "r");
  if (fp2 == NULL)
  {
    fprintf(stderr, "Cannot open signing key file.\n");
    exit(1);
  }

  OpenSSL_add_all_digests();

  char *keydata;
  int len;
  fseek(fp1, 0, SEEK_END);
  len = ftell(fp1);
  rewind(fp1);
  keydata = malloc(sizeof(char) * len);
  fread(keydata, 1, len, fp1);

  char *signkey;
  


  return 0;
}
