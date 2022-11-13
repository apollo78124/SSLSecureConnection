#include "copy.h"
#include "error.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/ssl.h>


void copy(SSL *from_fd, SSL *to_fd, size_t count)
{
    char buffer[1024] = {0};
    ssize_t rbytes;
    ssize_t wbytes;
    char echo1[256] = {0};

    while((rbytes = SSL_read(from_fd, buffer, count)) > 0)
    {

        printf("Client says: %s\n", buffer);
        wbytes = strlen(buffer);
        strcpy(echo1, buffer);
        for (int i = 0; echo1[i]!='\0'; i++) {
            if(echo1[i] >= 'a' && echo1[i] <= 'z') {
                echo1[i] = echo1[i] -32;
            }
        }
        printf("Echoing : %s\n", echo1);
        wbytes = SSL_write(from_fd, echo1, strlen(echo1) + 1);
        memset(buffer,0,strlen(buffer));
        memset(echo1,0,strlen(echo1));
        if(wbytes == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 4);
        }
    }

    if(rbytes == -1)
    {
        fatal_errno(__FILE__, __func__ , __LINE__, errno, 3);
    }
}
