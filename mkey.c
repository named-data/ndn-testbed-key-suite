#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ccn/ccn.h>
#include <ccn/signing.h>
#include <ccn/uri.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

static void
usage(const char *progname)
{
  fprintf(stderr,
      "%s [-h] [-c configure_file] [-i identity] [-a affiliation] [-f key_file] [-k signing_key] [-p key_prefix] [-x freshness_days]\n"
      "    Reads key, storing it to local repo with the given URI.\n"
      "    -h print this help message.\n"
      "    -c specify the configuration file.\n"
      "    -i specify the real-world identity of the key owner.\n"
      "    -a specify the affiliation of the key owner.\n"
      "    -f specify the public key file.\n"
      "    -k specify the signing key file.\n"
      "    -p specify the key name prefix.\n"
      "    -x specify the freshness in days.\n",
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
  bmem = BIO_new_mem_buf(input, len);
  bmem = BIO_push(b64, bmem);
  
  BIO_read(bmem, output, len);

  BIO_free_all(bmem);
}

static void
sha256(char *input, char *output)
{
  SHA256_CTX sha;

  SHA256_Init(&sha);
  SHA256_Update(&sha, input, strlen(input));
  SHA256_Final(output, &sha);
}

static void
extract_config(const xmlDocPtr doc, char **affl, char **prefix, char **signkey, int *fresh)
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

  cur = cur->xmlChildrenNode;
  while (cur != NULL)
  {
    if (!xmlStrcmp(cur->name, (const xmlChar *) "affiliation"))
    {
      if (*affl == NULL)
	*affl = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "prefix"))
    {
      if (*prefix == NULL)
	*prefix = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *) "signing_key"))
    {
      if (*signkey == NULL)
	*signkey = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
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
    cur = cur->next;
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
      extract_config(doc, &affiliation, &prefix, &signkey, &freshness);
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

  

  return 0;
}
