#include "copy.h"
#include "error.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/ssl.h>


void copy(SSL *from_fd, SSL *to_fd, size_t count)
{
    char buffer[1024] = {0};
    ssize_t rbytes;
    ssize_t wbytes;
    printf("Type message to server:\n");
    while(1)
    {
        fgets(buffer,254,stdin);
        rbytes = strlen(buffer);
        wbytes = SSL_write(to_fd, buffer, rbytes);
        rbytes = SSL_read(to_fd, buffer, count);
        printf("%s\n", buffer);
        memset(buffer,0,strlen(buffer));
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
