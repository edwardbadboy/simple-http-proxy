#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "add.h"

struct _add{
	int a;
	int b;
};

void initadd(struct add* ax)
{
	ax->true_add=malloc(sizeof(struct _add));
	ax->true_add->a=0;
	ax->true_add->b=2;
}

void printadd(struct add* ax)
{
	printf("add:a=%d add:b=%d\r\n",ax->true_add->a,ax->true_add->b);
}

void closeadd(struct add* ax)
{
	free(ax->true_add);
	ax->true_add=NULL;
}
