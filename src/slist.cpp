#include <stdlib.h>
#include <string.h>
#include "slist.h"

bool SListAppend(slist_t * slist, unsigned char* data, size_t data_size)
{
	if (slist == NULL || data == NULL || data_size == 0) {
		return false;
	}

	snode_t* node = (snode_t*)malloc(sizeof(void*) + data_size);
	if (node == NULL) {
	  return false;
	}
	memset(node , 0, sizeof(snode_t));

	memcpy(node->data, data, data_size);
	if (slist->last != NULL ) {
		slist->last->next = node;
	}
	
	slist->last = node;
	if (slist->first == NULL) {
		slist->first = node;
	}

	if (slist->current == NULL) {
		slist->current = node;
	}
	slist->count ++;
	return true;
}

unsigned char* SListNext(slist_t* slist)
{
	if (slist == NULL) {
		return NULL;
	}

	if (slist->current == NULL) {
		return NULL;
	}
	unsigned char* data = slist->current->data;
	slist->current = slist->current->next;
	return data;
}

void SListClear(slist_t* slist)
{
	if (slist == NULL || slist->first == NULL || slist->last == NULL)
		return;

	snode_t* current = slist->first;
	while(current != NULL) {
		snode_t* delete_node = current;
		current = current->next;
		free(delete_node);
		delete_node = NULL;
	}
	memset(slist, 0, sizeof(slist_t));
} 