/** 
 * a simple tool to extract public from ccnx keystore
 * user could send the output to site operator to be 
 * signed and published
 * Author: 
 *			Chaoyi Bian <bcy@pku.edu.cn> 
 *			Zhenkai Zhu <zhenkai@cs.ucla.edu> 
 */

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
usage(const char *progname)
{
  fprintf(stderr,
      "%s [-h] [-i ccnx_keystore_file] [-o output_file] [-p keystore_password]\n"
			"    -i specify input keystore file; by default it checks $HOME/.ccnx/.ccnx_keystore.\n"
			"    -o specify output file; by default it's output.pem.\n"
			"    -p specify the password for ccnx keystore; by default it's \"Th1s1sn0t8g00dp8ssw0rd.\".\n",
      progname);
  exit(1);
}

int main(int argc, char **argv) {

	const char *progname = argv[0];
	char *output = NULL;
	char *input = NULL;
	char *password = NULL;
	int res;

	while((res = getopt(argc, argv, "hi:o:p:")) != -1) {
		switch(res) {
			case 'i': input = strdup(optarg); break;
			case 'o': output = strdup(optarg); break;
			case 'p': password = strdup(optarg); break;
			case 'h': 
			default:
				usage(progname);
		}
	}

	if (input == NULL) {
		char *homedir = strdup(getenv("HOME"));
		size_t size = strlen("/.ccnx/.ccnx_keystore") + strlen(homedir);
		input = (char *)calloc(1, size + 1);
		sprintf(input, "%s/.ccnx/.ccnx_keystore", homedir);
	}

	FILE *fp = fopen(input, "rb");
	if (!fp) {
		fprintf(stderr, "%s does not exists or you do not have read permission\n", input);
		usage(progname);
	}
	
	PKCS12 *keystore;
	OpenSSL_add_all_algorithms();
	keystore = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (keystore == NULL) {
		fprintf(stderr, "%s: invalid keystore file\n", input);
		usage(progname);
	}

	if (password == NULL) {
		password = "Th1s1sn0t8g00dp8ssw0rd.";
	}
	EVP_PKEY *private_key;
	X509 *certificate;
	res = PKCS12_parse(keystore, password, &private_key, &certificate, NULL);
	PKCS12_free(keystore);
	if (res == 0) {
		fprintf(stderr, "Can not parse keystore %s\n", input);
		usage(progname);
	}

	if (output == NULL) {
		output = "output.pem";
	}
	fp = fopen(output, "w");
	res = PEM_write_X509(fp, certificate);
	fclose(fp);
	if (res == 0) {
		fprintf(stderr, "Can not create pem %s\n", output);
		usage(progname);
	}

	return 0;
}
