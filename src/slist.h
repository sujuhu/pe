#ifndef LIB_SLIST_H_
#define LIB_SLIST_H_

#ifndef ANYSIZE
#define ANYSIZE 	1
#endif

typedef struct _snode_t {
	struct _snode_t * next; //指向下一个节点
	unsigned char data[ANYSIZE];
}snode_t; 

typedef struct _slist_t {
	struct _snode_t * first;//指向第一个节点
	struct _snode_t * last; //指向最后一个节点
	struct _snode_t * current;
	int count;	
}slist_t;

bool SListAppend(slist_t * slist, unsigned char* data, size_t data_size);

unsigned char* SListNext(slist_t* slist);

void SListClear(slist_t* slist);
#endif