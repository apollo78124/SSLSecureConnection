#include "conversion.h"
#include "copy.h"
#include "error.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <malloc.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

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
SSL_CTX* InitCTX(void);
void ShowCerts(SSL* ssl);
static void cleanup(const struct options *opts);


#define DEFAULT_BUF_SIZE 1024
#define DEFAULT_PORT 5000


static volatile sig_atomic_t running;   // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)


int main(int argc, char *argv[])
{
    struct options opts;
    SSL_CTX *ctx;
    SSL *fd_out_ssl;
    SSL *fd_in_ssl;
    options_init(&opts);
    parse_arguments(argc, argv, &opts);
    options_process(&opts);

    /**
     * SSL Init
     */
    SSL_library_init();
    ctx = InitCTX();
    printf("SSL initialized, certificate and key loaded\n");


    fd_out_ssl = SSL_new(ctx);
    SSL_set_fd(fd_out_ssl, opts.fd_out);
    fd_in_ssl = SSL_new(ctx);
    SSL_set_fd(fd_in_ssl, opts.fd_in);
    if (SSL_connect(fd_out_ssl) == -1)   /* perform the connection */
    {
        ERR_print_errors_fp(stderr);

    }
    else {
              /* get any certificates */
        ShowCerts(fd_out_ssl);
        copy(fd_in_ssl, fd_out_ssl, opts.buffer_size);
    }

    SSL_free(fd_out_ssl);
    SSL_free(fd_in_ssl);
    SSL_CTX_free(ctx);
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

    if(opts->ip_out)
    {
        int result;
        struct sockaddr_in addr;

        opts->fd_out = socket(AF_INET, SOCK_STREAM, 0);

        if(opts->fd_out == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        addr.sin_family = AF_INET;
        addr.sin_port = htons(opts->port_out);
        addr.sin_addr.s_addr = inet_addr(opts->ip_out);

        if(addr.sin_addr.s_addr ==  (in_addr_t)-1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }

        result = connect(opts->fd_out, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

        if(result == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
        }
    }
}


SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
    {
        printf("Info: No client certificates configured.\n");
    }
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

