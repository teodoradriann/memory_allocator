
#include <stdio.h>
struct block_meta {
	size_t size;
	int status;
	struct block_meta *prev;
	struct block_meta *next;
};
int main () {
    int i = sizeof(int);
    printf("%d", i);
}