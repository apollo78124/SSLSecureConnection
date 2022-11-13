#include "copy.h"
#include "error.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>


void copy(int from_fd, int to_fd, size_t count)
{
    char buffer[1024] = {0};
    ssize_t rbytes;
    char echo1[256] = {0};

    if(buffer == NULL)
    {
        fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
    }

    while((rbytes = read(from_fd, buffer, count)) > 0)
    {
        ssize_t wbytes;
        wbytes = write(to_fd, buffer, rbytes);
        strcpy(echo1, buffer);
        for (int i = 0; echo1[i]!='\0'; i++) {
            if(echo1[i] >= 'a' && echo1[i] <= 'z') {
                echo1[i] = echo1[i] -32;
            }
        }

        wbytes = write(from_fd, echo1, strlen(echo1) + 1);
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
