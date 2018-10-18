/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The covert channel server to receive and decrypt data
 */

#include <assert.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

static unsigned char key[KEY_LEN];

/*
 * function:
 *    main
 *
 * return:
 *    int
 *
 * parameters:
 *    void
 *
 * notes:
 * Handles daemonization and forking into read and raw servers.
 * Read server establishes a TLS session and discards any incoming data.
 * Raw server parses TCP timestamp values and decrypts the resulting data.
 */
int main(void) {
#if 0
    //Daemonize
    switch (fork()) {
        case 0:
            //Child
            break;
        case -1:
            perror("fork()");
            exit(EXIT_FAILURE);
        default:
            //Parent
            exit(EXIT_SUCCESS);
    }
#endif

    memset(key, 0xab, KEY_LEN);

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    //TCP recv loop
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sin;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);

    if (bind(listen_sock, (struct sockaddr*) &sin, sizeof(struct sockaddr_in)) == -1) {
        perror("bind");
        return EXIT_FAILURE;
    }
    listen(listen_sock, 5);

    int conn_sock = accept(listen_sock, NULL, 0);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, conn_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    unsigned char buffer[MAX_PAYLOAD];

    switch (fork()) {
        case 0: {
            setvbuf(stdin, NULL, _IONBF, 0);
            for (;;) {
                int size = read(STDIN_FILENO, buffer, MAX_PAYLOAD);
                if (size < 0) {
                    perror("read");
                    break;
                }
                if (size == 0) {
                    break;
                }
                SSL_write(ssl, buffer, size);
            }
        } break;
        case -1:
            perror("fork()");
            exit(EXIT_FAILURE);
        default: {
            int size;
            while ((size = SSL_read(ssl, buffer, MAX_PAYLOAD)) > 0) {
                for (int i = 0; i < size; ++i) {
                    printf("%c", buffer[i]);
                }
            }
        } break;
    }
    setvbuf(stdin, NULL, _IOLBF, 0);

    SSL_free(ssl);

    close(listen_sock);

    SSL_CTX_free(ctx);

    cleanup_openssl();

    return EXIT_SUCCESS;
}