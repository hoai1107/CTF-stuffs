#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<time.h>


int main(){
	uint32_t rand_val;
	srand(time(0));

	for(int i=0;i<30;++i){
		rand_val = rand() & 0xf;
		printf("%d\n",rand_val);
	}

	return 0;
}

//gcc solve.c -o solve
// ./solve && nc jupiter.challenges.picoctf.org 34558