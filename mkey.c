#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ccn/ccn.h>
#include <ccn/signing.h>
#include <ccn/uri.h>

static void
usage(const char *progname)
{
  fprintf(stderr,
      "%s [-h] [-c configure_file] [-i identity] [-a affiliation] [-f key_file] [-k key_uri] [-x freshness_seconds] ccnx:/some/uri\n"
      "    Reads key, storing it to local repo with the given URI.\n"
      "    -h print this help message.\n"
      "    -i specify the real-world identity of the key owner.\n"
      "    -a specify the affiliation of the key owner.\n"
      "    -f specify the key file.\n",
      progname);
  exit(1);
}


int main(int argc, char **argv)
{
  const char *progname = argv[0];
  struct ccn *ccn = NULL;
  int res;
  char *identity = NULL;
  char *affiliation = NULL;
  char *keyfile = NULL;
  struct ccn_charbuf *name;
  
  while ((res = getopt(argc, argv, "h:i:a:f:")) != -1)
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
      case 'h':
      default:
	usage(progname);
	break;
    }

  argc -= optind;
  argv += optind;
  if (argc != 1)
    usage(progname);

  name = ccn_charbuf_create();
  res = ccn_name_from_uri(name, argv[0]);
  if (res < 0)
  {
    fprintf(stderr, "%s: bad CCN URI: %s\n", progname, argv[0]);
    exit(1);
  }



  return 0;
}
