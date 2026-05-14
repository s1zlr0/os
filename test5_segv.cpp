#define TEST5_EXPOSE_KEY_ADDR
#include "caesar.h"
#include <cstdio>
int main(){
    set_key(42);
    char* p=(char*)get_key_mem_addr();
    printf("Attempting write to protected key memory at %p...\n",(void*)p); fflush(stdout);
    *p=1;
    printf("ERROR: should not reach here\n"); return 0;
}
