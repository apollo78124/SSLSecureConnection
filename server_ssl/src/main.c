#include "conversion.h"
#include "copy.h"
#include "error.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <unistd.h>
#include <malloc.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

/**
 * sudo dnf install openssl-devel
 *
 */

struct options
{
    char *file_name;
    char *ip_in;
    char *ip_out;
    in_port_t port_in;
    in_port_t port_out;
    int fd_in;
    int fd_out;
    size_t buffer_size;
};


static void options_init(struct options *opts);
static void parse_arguments(int argc, char *argv[], struct options *opts);
static void options_process(struct options *opts);
static SSL_CTX* InitServerCTX(SSL_CTX *ctx);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
static void cleanup(const struct options *opts);
static void set_signal_handling(struct sigaction *sa);
static void signal_handler(int sig);
void Servlet(SSL* fd_in_ssl, SSL* fd_to_ssl, struct options *opts);


#define DEFAULT_BUF_SIZE 1024
#define DEFAULT_PORT 5000
#define BACKLOG 5


static volatile sig_atomic_t running;   // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)


int main(int argc, char *argv[])
{
    struct options opts;
    SSL_CTX *ctx;
    options_init(&opts);
    parse_arguments(argc, argv, &opts);
    options_process(&opts);

    /**
     * SSL Init
     */
    SSL_library_init();
    ctx = InitServerCTX(&ctx);
    LoadCertificates(ctx, "../../../cert.pem", "../../../key.pem");
    printf("SSL initialized, certificate and key loaded\n");

    if(opts.ip_in)
    {
        struct sigaction sa;

        set_signal_handling(&sa);
        running = 1;

        while(running)
        {
            int fd;
            struct sockaddr_in accept_addr;
            socklen_t accept_addr_len;
            char *accept_addr_str;
            in_port_t accept_port;
            SSL *fd_from_ssl;
            SSL *fd_to_ssl;

            accept_addr_len = sizeof(accept_addr);
            fd = accept(opts.fd_in, (struct sockaddr *)&accept_addr, &accept_addr_len);

            if(fd == -1)
            {
                if(errno == EINTR)
                {
                    break;
                }

                fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
            }

            accept_addr_str = inet_ntoa(accept_addr.sin_addr);  // NOLINT(concurrency-mt-unsafe)
            accept_port = ntohs(accept_addr.sin_port);
            printf("Accepted from %s:%d\n", accept_addr_str, accept_port);


            fd_from_ssl = SSL_new(ctx);
            fd_to_ssl = SSL_new(ctx);
            SSL_set_fd(fd_from_ssl, fd);      /* set connection socket to SSL state */
            SSL_set_fd(fd_to_ssl, opts.fd_out);

            if (SSL_accept(fd_from_ssl) == -1)     /* do SSL-protocol accept */
            {
                ERR_print_errors_fp(stderr);
            }
            else
            {
                printf("SSL connection established\n");
                ShowCerts(fd_to_ssl);        /* get any certificates */
                copy(fd_from_ssl, fd_to_ssl, opts.buffer_size);
            }

            printf("Closing %s:%d\n", accept_addr_str, accept_port);
            SSL_free(fd_from_ssl);
            SSL_CTX_free(ctx);
            close(fd);
        }
    }

    cleanup(&opts);

    return EXIT_SUCCESS;
}


static void options_init(struct options *opts)
{
    memset(opts, 0, sizeof(struct options));
    opts->fd_in       = STDIN_FILENO;
    opts->fd_out      = STDOUT_FILENO;
    opts->port_in     = DEFAULT_PORT;
    opts->port_out    = DEFAULT_PORT;
    opts->buffer_size = DEFAULT_BUF_SIZE;
}


static void parse_arguments(int argc, char *argv[], struct options *opts)
{
    int c;

    while((c = getopt(argc, argv, ":i:o:p:P:b:")) != -1)   // NOLINT(concurrency-mt-unsafe)
    {
        switch(c)
        {
            case 'i':
            {
                opts->ip_in = optarg;
                break;
            }
            case 'o':
            {
                opts->ip_out = optarg;
                break;
            }
            case 'p':
            {
                opts->port_in = parse_port(optarg, 10); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                break;
            }
            case 'P':
            {
                opts->port_out = parse_port(optarg, 10); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                break;
            }
            case 'b':
            {
                opts->buffer_size = parse_size_t(optarg, 10); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                break;
            }
            case ':':
            {
                fatal_message(__FILE__, __func__ , __LINE__, "\"Option requires an operand\"", 5); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
                break;
            }
            case '?':
            {
                fatal_message(__FILE__, __func__ , __LINE__, "Unknown", 6); // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
            }
            default:
            {
                assert("should not get here");
            };
        }
    }

    if(optind < argc)
    {
        opts->file_name = argv[optind];
    }
}


static void options_process(struct options *opts)
{
    if(opts->file_name && opts->ip_in)
    {
        fatal_message(__FILE__, __func__ , __LINE__, "Can't pass -i and a filename", 2);
    }

    if(opts->ip_in)
    {
        struct sockaddr_in addr;
        int result;
        int option;
        opts->fd_in = socket(AF_INET, SOCK_STREAM, 0);

        if(opts->fd_in == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(opts->port_in);
        addr.sin_addr.s_addr = inet_addr(opts->ip_in);

        if(addr.sin_addr.s_addr ==  (in_addr_t)-1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        option = 1;
        setsockopt(opts->fd_in, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

        result = bind(opts->fd_in, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

        if(result == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        result = listen(opts->fd_in, BACKLOG);

        if(result == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }
    }
}

static SSL_CTX* InitServerCTX(SSL_CTX *ctx)
{   SSL_METHOD *method;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}


static void cleanup(const struct options *opts)
{
    if(opts->file_name || opts->ip_in)
    {
        close(opts->fd_in);
    }

    if(opts->ip_out)
    {
        close(opts->fd_out);
    }
}


static void set_signal_handling(struct sigaction *sa)
{
    int result;

    sigemptyset(&sa->sa_mask);
    sa->sa_flags = 0;
    sa->sa_handler = signal_handler;
    result = sigaction(SIGINT, sa, NULL);

    if(result == -1)
    {
        fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
    }
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void signal_handler(int sig)
{
    running = 0;
}
#pragma GCC diagnostic pop

