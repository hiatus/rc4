#include "rc4.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define MAX_BUFF 32768
#define MAX_LOAD 4294967296

struct rc4_opts {
	uint8_t hex;

	size_t stream;
	size_t skip;

	uint8_t *key;

	FILE *in;
};

const char banner[] =
"rc4 [options] [file]?\n"
"	Generate an RC4 byte stream and XOR it with [file] or stdin\n\n"

"	-h         help\n"
"	-x         assume -k [str] to be raw bytes represented in hex\n"
"	-k [str]   use the string [str] as RC4 key\n"
"	-K [path]  read RC4 key from a file at [path]\n"
"	-s [int]   generate [int] stream bytes (no XOR, input ignored)\n"
"	-S [int]   skip the first [int] stream bytes\n";

static uint8_t *_load_file(const char *path, size_t *size)
{
	FILE *fp;
	uint8_t *data;

	if (! (fp = fopen(path, "rb"))) {
		fprintf(stderr, "[err] Failed to open '%s", path);
		perror("'");
		return NULL;
	}

	fseek(fp, 0, SEEK_END);

	if ((*size = ftell(fp)) > MAX_LOAD) {
		fprintf(
			stderr,
			"[err] '%s' is too large (over %zu bytes)\n",
			path, MAX_LOAD
		);

		fclose(fp);
		return NULL;
	}

	if (! (data = malloc(*size))) {
		perror("[err] malloc");

		fclose(fp);
		return NULL;
	}

	rewind(fp);

	if (fread(data, 1, *size, fp) != *size) {
		fprintf(
			stderr,
			"[err] Failed to read %zu bytes from key file\n", *size
		);

		fclose(fp);
		free(data);

		return NULL;
	}

	fclose(fp);

	return data;
}

static int _hex_to_raw(const char *hex, uint8_t *data)
{
	char byte[3] = {0x00, 0x00, 0x00};

	for (size_t hi = 0, di = 0; hex[hi]; hi += 2, ++di) {
		if (! isxdigit(hex[hi]))
			return 1;

		if (hex[hi + 1]) {
			if (! isxdigit(hex[hi + 1]))
				return 1;

			byte[0] = hex[hi];
			byte[1] = hex[hi + 1];
		}
		else {
			byte[0] = '0';
			byte[1] = hex[hi];
		}

		data[di] = strtoul(byte, NULL, 16);
	}

	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	int ret = 0;

	size_t len;
	size_t len_key = 0;

	struct rc4_ctx ctx;

	struct rc4_opts opts = {
		.hex = 0,
		.stream = 0,
		.skip = 0,
		.key = NULL,
		.in = stdin
	};

	uint8_t buffer[MAX_BUFF];

	if (argc == 1) {
		fputs(banner, stderr);
		return EXIT_FAILURE;
	}

	while ((opt = getopt(argc, argv, ":hxk:K:s:S:")) != -1) {
		switch (opt) {
			case 'h':
				ret = EXIT_SUCCESS;
				fputs(banner, stderr);

				goto cleanup;

			case 'x':
				opts.hex = 1;
				break;

			case 'k':
				if (! (len_key = strlen(optarg))) {
					ret = EXIT_FAILURE;
					fputs("[err] Zero-length key\n", stderr);

					goto cleanup;
				}

				if (opts.hex)
					len_key /= 2;

				if (! (opts.key = malloc(len_key + 1))) {
					ret = EXIT_FAILURE;
					perror("malloc");

					goto cleanup;
				}

				if (! opts.hex)
					strncpy((char *)opts.key, optarg, len_key);

				else if (opts.hex && _hex_to_raw(optarg, opts.key)) {
					ret = EXIT_FAILURE;
					fprintf(stderr, "[err] Invalid hex string: '%s'\n", optarg);

					goto cleanup;
				}

				break;

			case 'K':
				if (opts.stream)
					break;

				opts.key = _load_file(optarg, &len_key);

                                if (! opts.key || ! len_key) {
					ret = EXIT_FAILURE;

					if (! len_key)
						fputs("[err] Empty key file\n", stderr);

                                        goto cleanup;
                                }

                                break;

			case 's':
				if (! (opts.stream = strtoul(optarg, NULL, 16))) {
					fputs("[err] Invalid stream length\n", stderr);
					goto cleanup;
				}

				break;

			case 'S':
				if (! (opts.skip = strtoul(optarg, NULL, 16))) {
					fputs("[err] Invalid skip size\n", stderr);
					goto cleanup;
				}

				break;

			case ':':
				ret = EXIT_FAILURE;

				fprintf(
					stderr,
					"[err] Option '%c' requires an argument\n", optopt
				);

				goto cleanup;;

			case '?':
				ret = EXIT_FAILURE;
				fprintf(stderr, "[err] Invalid option: '%c'\n", optopt);

				goto cleanup;
		}
	}

	if (! opts.key || ! len_key) {
		ret = EXIT_FAILURE;
		fputs("[err] No key provided\n", stderr);

		goto cleanup;
	}

	rc4_init(&ctx, opts.key, len_key);
	rc4_skip(&ctx, opts.skip);

	if (opts.stream) {
		while (opts.stream > MAX_BUFF) {
			rc4_stream(&ctx, buffer, MAX_BUFF);
			fwrite(buffer, 1, MAX_BUFF, stdout);

			opts.stream -= MAX_BUFF;
		}

		if (opts.stream) {
			rc4_stream(&ctx, buffer, opts.stream);
			fwrite(buffer, 1, opts.stream, stdout);
		}

		goto cleanup;
	}

	if (optind <= argc - 1 && ! (opts.in = fopen(argv[optind], "rb"))) {
		ret = EXIT_FAILURE;
		fprintf(stderr, "[err] Failed to open '%s", argv[optind]);
		perror("'");

		goto cleanup;
	}

	for (size_t off = 0; (len = fread(buffer, 1, MAX_BUFF, opts.in)) > 0; off += len) {
		rc4_crypt(&ctx, buffer, len);
		fwrite(buffer, 1, len, stdout);
	}

cleanup:
	if (opts.key)
		free(opts.key);

	if (opts.in && opts.in != stdin)
		fclose(opts.in);

	return ret;
}
