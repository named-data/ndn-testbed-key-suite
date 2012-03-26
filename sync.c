/*
 * =====================================================================================
 *
 *       Filename:  sync.c
 *
 *    Description:  Create slice for key synchronization
 *
 *        Version:  1.0
 *        Created:  03/25/2012 05:36:16 PM
 *
 *         Author:  Chaoyi Bian, bcy@pku.edu.cn
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/digest.h>

#define SLICE_VERSION 20120325

static int
local_store(struct ccn *ccn, struct ccn_charbuf *nm, struct ccn_charbuf *cb)
{
  int res = 0;
  struct ccn_charbuf *tmp = ccn_charbuf_create();

  ccn_create_version(ccn, nm, CCN_V_NOW, 0, 0);
  ccn_charbuf_append_charbuf(tmp, nm);
  ccn_name_from_uri(tmp, "%C1.R.sw");
  ccn_name_append_nonce(tmp);
  res |= ccn_get(ccn, tmp, NULL, 6000, NULL, NULL, NULL, 0);
  ccn_charbuf_destroy(&tmp);
  
  struct ccn_charbuf *cob = ccn_charbuf_create();
  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  const void *cp = NULL;
  size_t cs = 0;

  if (cb != NULL)
  {
    sp.type = CCN_CONTENT_DATA;
    cp = (const void *) cb->buf;
    cs = cb->length;
  }
  else
    sp.type = CCN_CONTENT_GONE;

  res |= ccn_name_append_numeric(nm, CCN_MARKER_SEQNUM, 0);
  sp.sp_flags |= CCN_SP_FINAL_BLOCK;
  res |= ccn_sign_content(ccn, cob, nm, &sp, cp, cs);
  res |= ccn_put(ccn, (const void *) cob->buf, cob->length);
  ccn_charbuf_destroy(&cob);

  return res;
}

static void
send_slice(const char *topo, const char *prefix)
{
  struct ccn_charbuf *cb = ccn_charbuf_create();
  struct ccn_charbuf *hash = ccn_charbuf_create();
  struct ccn_charbuf *nm = ccn_charbuf_create();
  int i = 0;
  int res = 0;

  res |= ccnb_element_begin(cb, CCN_DTAG_SyncConfigSlice);
  res |= ccnb_tagged_putf(cb, CCN_DTAG_SyncVersion, "%u", SLICE_VERSION);
  res |= ccn_name_from_uri(nm, topo);
  res |= ccn_charbuf_append_charbuf(cb, nm);
  res |= ccn_name_from_uri(nm, prefix);
  res |= ccn_charbuf_append_charbuf(cb, nm);
  res |= ccnb_element_begin(cb, CCN_DTAG_SyncConfigSliceList);
  res |= ccnb_element_end(cb);
  res |= ccnb_element_end(cb);

  if (res < 0)
  {
    fprintf(stderr, "Create slice failed.\n");
    exit(1);
  }

  struct ccn *ccn = NULL;
  struct ccn_digest *cow = ccn_digest_create(CCN_DIGEST_DEFAULT);
  size_t sz = ccn_digest_size(cow);
  unsigned char *dst = ccn_charbuf_reserve(hash, sz);
  ccn_digest_init(cow);
  ccn_digest_update(cow, cb->buf, cb->length);
  ccn_digest_final(cow, dst, sz);
  hash->length = sz;
  ccn_digest_destroy(&cow);

  char *localLit = "\xC1.M.S.localhost";
  char *sliceCmd = "\xC1.S.cs";
  res |= ccn_name_init(nm);
  res |= ccn_name_append_str(nm, localLit);
  res |= ccn_name_append_str(nm, sliceCmd);
  res |= ccn_name_append(nm, hash->buf, hash->length);

  ccn = ccn_create();
  if (ccn_connect(ccn, NULL) == -1)
  {
    fprintf(stderr, "Could not connect to ccnd\n");
    exit(1);
  }
  if (res >= 0)
    res |= local_store(ccn, nm, cb);
  if (res < 0)
  {
    fprintf(stderr, "Create slice failed.\n");
    exit(1);
  }
  
  ccn_destroy(&ccn);
  ccn_charbuf_destroy(&cb);
  ccn_charbuf_destroy(&hash);
  ccn_charbuf_destroy(&nm);
}

static void
usage(const char *progname)
{
  fprintf(stderr,
      "%s [-h] [-p prefix]"
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
  int res;
  
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

  send_slice(topo, prefix);
  return 0;
}
