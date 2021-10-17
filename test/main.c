// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "host.h"

int main(int argc, const char* argv[])
{
    
    printf("CPM test tool %s %s\n", __DATE__, __TIME__);
    int result = create_enclave(argc, argv);
    if (result != 0)
    {
        fprintf(stderr, "Failed to create enclave with result = %i.\n", result);

        return result;
    }

    
    cpk_run_tests();
   
    result = terminate_enclave();
    if (result != 0)
    {
        fprintf(
            stderr, "Failed to terminate enclave with result = %i.\n", result);
    }

    return result;
}
