#include "copy.h"
#include "error.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>


void copy(int from_fd, int to_fd, size_t count)
{
    char buffer[1024] = {0};
    ssize_t rbytes;

    if(buffer == NULL)
    {
        fatal_errno(__FILE__, __func__ , __LINE__, errno, 2);
    }

    while((rbytes = read(from_fd, buffer, count)) > 0)
    {
        ssize_t wbytes;
        wbytes = write(to_fd, buffer, rbytes);
        rbytes = read(to_fd, buffer, count);
        printf("%s", buffer);
        if(wbytes == -1)
        {
            fatal_errno(__FILE__, __func__ , __LINE__, errno, 4);
        }
    }

    if(rbytes == -1)
    {
        fatal_errno(__FILE__, __func__ , __LINE__, errno, 3);
    }

    free(buffer);
}
