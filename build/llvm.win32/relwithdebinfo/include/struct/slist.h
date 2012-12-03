#ifndef _SLIST_H_KIMZHANG
#define _SLIST_H_KIMZHANG
/*
 * Lock-less NULL terminated single linked list
 *
 * If there are multiple producers and multiple consumers, llist_add
 * can be used in producers and llist_del_all can be used in
 * consumers.  They can work simultaneously without lock.  But
 * llist_del_first can not be used here.  Because llist_del_first
 * depends on list->first->next does not changed if list->first is not
 * changed during its operation, but llist_del_first, llist_add,
 * llist_add (or llist_del_all, llist_add, llist_add) sequence in
 * another consumer may violate that.
 *
 * If there are multiple producers and one consumer, llist_add can be
 * used in producers and llist_del_all or llist_del_first can be used
 * in the consumer.
 *
 * This can be summarized as follow:
 *
 *           |   add    | del_first |  del_all
 * add       |    -     |     -     |     -
 * del_first |          |     L     |     L
 * del_all   |          |           |     -
 *
 * Where "-" stands for no lock is needed, while "L" stands for lock
 * is needed.
 *
 * The list entries deleted via llist_del_all can be traversed with
 * traversing function such as llist_for_each etc.  But the list
 * entries can not be traversed safely before deleted from the list.
 * The order of deleted entries is from the newest to the oldest added
 * one.  If you want to traverse from the oldest to the newest, you
 * must reverse the order by yourself before traversing.
 *
 * The basic atomic operation of this list is cmpxchg on long.  On
 * architectures that don't have NMI-safe cmpxchg implementation, the
 * list can NOT be used in NMI handlers.  So code that uses the list in
 * an NMI handler should depend on CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.
 *
 */

#include "cmpxchg.h"
#include "contain.h"

typedef struct slist_node {
	struct slist_node *next;
}snode_t;

typedef struct slist_head {
	struct slist_node *first;
}slist_t;

#define SLIST_HEAD_INIT(name)	{ NULL }
#define SLIST_HEAD(name)	slist_t name = SLIST_HEAD_INIT(name)

/**
 * slist_init - initialize lock-less list head
 * @list:	the head for your lock-less list
 */
static inline void slist_init(slist_t *list)
{
	list->first = NULL;
}

/**
 * llist_entry - get the struct of this entry
 * @ptr:	the &struct llist_node pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the llist_node within the struct.
 */
#define slist_entry(ptr, type, member)		\
	container_of(ptr, type, member)

/**
 * llist_for_each - iterate over some deleted entries of a lock-less list
 * @pos:	the &struct llist_node to use as a loop cursor
 * @node:	the first entry of deleted list entries
 *
 * In general, some entries of the lock-less list can be traversed
 * safely only after being deleted from list, so start with an entry
 * instead of list head.
 *
 * If being used on entries deleted from lock-less list directly, the
 * traverse order is from the newest to the oldest added entry.  If
 * you want to traverse from the oldest to the newest, you must
 * reverse the order by yourself before traversing.
 */
#define slist_for_each(pos, node)			\
	for ((pos) = (node); pos; (pos) = (pos)->next)

/**
 * llist_for_each_entry - iterate over some deleted entries of lock-less list of given type
 * @pos:	the type * to use as a loop cursor.
 * @node:	the fist entry of deleted list entries.
 * @member:	the name of the llist_node with the struct.
 *
 * In general, some entries of the lock-less list can be traversed
 * safely only after being removed from list, so start with an entry
 * instead of list head.
 *
 * If being used on entries deleted from lock-less list directly, the
 * traverse order is from the newest to the oldest added entry.  If
 * you want to traverse from the oldest to the newest, you must
 * reverse the order by yourself before traversing.
 */
/*
#define slist_for_each_entry(pos, node, member)				\
	for ((pos) = slist_entry((node), typeof(*(pos)), member);	\
	     &(pos)->member != NULL;					\
	     (pos) = slist_entry((pos)->member.next, typeof(*(pos)), member))
*/
#define slist_for_each_entry(pos, list, type, member_entry, member_node)   \
  	for ((pos) = slist_first_entry((list), type, member_entry, member_node); \
  		(pos) != NULL; \
  		(pos) = slist_next_entry((pos), type, member_entry, member_node)) 

#define slist_first_entry(list, type, member_entry, member_node)  \
	(list)->first == NULL ? \
		NULL : \
		&((type*)slist_entry((list)->first, type, member_node))->member_entry

#define slist_next_entry(entry, type, member_entry, member_node) 	\
  slist_next(&(((type*)container_of(entry, type, member_entry))->member_node)) == NULL?\
  NULL:\
  &(((type*)container_of(slist_next(&(((type*)container_of(entry, type, member_entry))->member_node)), type, member_node))->member_entry)



/**
 * llist_empty - tests whether a lock-less list is empty
 * @head:	the list to test
 *
 * Not guaranteed to be accurate or up to date.  Just a quick way to
 * test whether the list is empty without deleting something from the
 * list.
 */
static inline bool slist_empty(const slist_t *head)
{
	return head->first == NULL;
}

static inline snode_t *slist_next(snode_t *node)
{
	return node->next;
}

/**
 * llist_add - add a new entry
 * @head:	the head for your lock-less list
 * @new:	new entry to be added
 *
 * Returns true if the list was empty prior to adding this entry.
 */
static inline bool slist_add(slist_t *head, snode_t *new_node)
{
	snode_t *entry, *old_entry;

	entry = head->first;
	for (;;) {
		old_entry = entry;
		new_node->next = entry;

		entry = (snode_t*)cmpxchg(&head->first, old_entry, new_node);
		if (entry == old_entry)
			break;
	}

	return old_entry == NULL;
}


/**
 * llist_del_all - delete all entries from lock-less list
 * @head:	the head of lock-less list to delete all entries
 *
 * If list is empty, return NULL, otherwise, delete all entries and
 * return the pointer to the first entry.  The order of entries
 * deleted is from the newest to the oldest added one.
 */
static inline snode_t *slist_del_all(slist_t *head)
{
	return (snode_t*)xchg(&head->first, 0);
}


#define slist_for_each_safe(var, list, type, member)   \
     for(snode_t *i =(list)->first, *t = NULL; \
    i != NULL && ((t = i->next) == NULL || t != NULL) && ((var) = container_of(i, type, member)) != NULL; \
    i = t, slist_del_all(list))

#endif /* LLIST_H */
