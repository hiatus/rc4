librc4
======
Portable and fast (enough) implementation of the RC4 cipher.

API
---
```
// Initialize RC4 context
void rc4_init(struct rc4_ctx *ctx, const uint8_t *key, size_t len);

// Skip stream bytes
void rc4_skip(struct rc4_ctx *ctx, size_t len);

// Get stream bytes
void rc4_stream(struct rc4_ctx *ctx, void *buffer, size_t len);

// Encrypt or decrypt a buffer
void rc4_crypt(struct rc4_ctx *ctx, void *buffer, size_t len);
```

CLI Tool
--------
Compile the provided CLI tool which puts the cipher functions to use.
```
$ git clone https://github.com/hiatus/rc4.git && cd rc4 && make
```

- Run it
```
$ ./bin/rc4 -h
```
