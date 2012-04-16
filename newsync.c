#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/sync.h>

static void
usage(const char *progname)
{
  fprintf(stderr,
      "%s [-h] [-t topo] [-p prefix]"
      " Create the slice for sychronization of keys.\n"
      " -h - print this message and exit\n"
      " -t topo - set the topo prefix, default /ndn/keys\n"
      " -p prefix - set the name prefix, default /ndn/keys\n",
      progname);
  exit(1);
}

int main(int argc, char **argv)
{
  char *progname = argv[0];
  char *topo = NULL;
  char *prefix = NULL;
  int res = 0;
  struct ccn *ccn = NULL;
  struct ccns_slice *sync = NULL;
  
  while ((res = getopt(argc, argv, "hpt:")) != -1)
  {
    switch (res)
    {
      case 'p':
	prefix = strdup(optarg);
	break;
      case 't':
	topo = strdup(optarg);
	break;
      case 'h':
      default:
	usage(progname);
	break;
    }
  }

  if (prefix == NULL)
    prefix = strdup("/ndn/keys");
  if (topo == NULL)
    topo = strdup("/ndn/keys");

  sync = ccns_slice_create();
  ccn = ccn_create();
  if (ccn == NULL || ccn_connect(ccn, NULL) == -1)
  {
    fprintf(stderr, "Could not connect to ccn handle.\n");
    exit(1);
  }

  struct ccn_charbuf *t = ccn_charbuf_create();
  res |= ccn_name_from_uri(t, topo);
  struct ccn_charbuf *p = ccn_charbuf_create();
  res |= ccn_name_from_uri(p, prefix);

  if (res != 0)
  {
    fprintf(stderr, "topo or prefix is invalid");
    exit(1);
  }
  
  res |= ccns_slice_set_topo_prefix(sync, t, p);

  struct ccn_charbuf *name = ccn_charbuf_create();
  ccns_slice_name(name, sync);

  struct ccns_slice *tmp = ccns_slice_create();
  if (ccns_read_slice(ccn, name, tmp) != 0)
  {
    res |= ccns_write_slice(ccn, sync, name);
    if (res != 0)
    {
      fprintf(stderr, "Create slice failed.");
      exit(1);
    }
  }

  ccn_charbuf_destroy(&t);
  ccn_charbuf_destroy(&p);
  ccn_charbuf_destroy(&name);
  ccns_slice_destroy(&tmp);
  ccns_slice_destroy(&sync);
  ccn_destroy(&ccn);
  free(topo);
  free(prefix);
  
  return 0;
}
