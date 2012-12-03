#ifndef _DLIST_H_KIMZHANG
#define _DLIST_H_KIMZHANG
#include "contain.h"
/*
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/poison.h>
#include <linux/const.h>
*/

#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif

/*
 * Architectures might want to move the poison pointer offset
 * into some well-recognized area such as 0xdead000000000000,
 * that is also not mappable by user-space exploits:
 */
#ifdef CONFIG_ILLEGAL_POINTER_VALUE
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)
#else
# define POISON_POINTER_DELTA 0
#endif

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((void *) 0x00100100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x00200200 + POISON_POINTER_DELTA)

typedef struct list_head {
	struct list_head *next, *prev;
}dlist_t, dnode_t;


/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

#define DLIST_HEAD_INIT(name) { &(name), &(name) }

#define DLIST_HEAD(name) \
	dlist_t name = DLIST_HEAD_INIT(name)

static inline void dlist_init(dlist_t *list)
{
	list->next = list;
	list->prev = list;
}

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(dnode_t *entry, dnode_t *prev, dnode_t *next)
{
	next->prev = entry;
	entry->next = next;
	entry->prev = prev;
	prev->next = entry;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void dlist_add(dlist_t *list, dnode_t *entry)
{
	__list_add(entry, list, list->next);
}


/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void dlist_add_tail(dlist_t *list, dnode_t *entry)
{
	__list_add(entry, list->prev, list);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_remove(dnode_t * prev, dnode_t* next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void __list_remove_entry(dnode_t *entry)
{
	__list_remove(entry->prev, entry->next);
}

static inline void dlist_remove(dnode_t *entry)
{
	__list_remove(entry->prev, entry->next);
	entry->next = entry; /*LIST_POISON1;*/
	entry->prev = entry; /*LIST_POISON2;*/
	dlist_init(entry);
}

/**
 * list_replace - replace old entry by new one
 * @old : the element to be replaced
 * @new : the new element to insert
 *
 * If @old was empty, it will be overwritten.
 */
static inline void dlist_replace(dnode_t *old_entry, dnode_t *new_entry)
{
	new_entry->next = old_entry->next;
	new_entry->next->prev = new_entry;
	new_entry->prev = old_entry->prev;
	new_entry->prev->next = new_entry;
	dlist_init(old_entry);
}

/**
 * list_move - delete from one list and add as another's head
 * @entry: the entry to move
 * @new_list: the head that will precede our entry
 */
static inline void dlist_move(dlist_t *new_list, dnode_t *entry)
{
	__list_remove_entry(entry);
	dlist_add(new_list, entry);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @entry: the entry to move
 * @new_list: the head that will follow our entry
 */
static inline void dlist_move_tail(dlist_t *new_list, dnode_t *entry)
{
	__list_remove_entry(entry);
	dlist_add_tail(new_list, entry);
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline 
bool dlist_is_last_entry(const dlist_t *list, const dnode_t *entry)
{
	return entry->next == list;
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline bool dlist_empty(const dlist_t *list)
{
	return list->next == list;
}

/**
 * list_empty_careful - tests whether a list is empty and not being modified
 * @head: the list to test
 *
 * Description:
 * tests whether a list is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is list_del_init(). Eg. it cannot be used
 * if another CPU could re-list_add() it.
 */
static inline bool dlist_empty_careful(const dlist_t *head)
{
	dnode_t *next = head->next;
	return (next == head) && (next == head->prev);
}

/**
 * list_rotate_left - rotate the list to the left
 * @head: the head of the list
 */
static inline void dlist_rotate_left(dlist_t *list)
{
	dnode_t *first = NULL;

	if (!dlist_empty(list)) {
		first = list->next;
		dlist_move_tail(first, list);
	}
}

/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline bool dlist_is_singular(const dlist_t *head)
{
	return !dlist_empty(head) && (head->next == head->prev);
}

static inline 
void __list_cut_position(dlist_t *list, dlist_t *head, dnode_t *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}

/**
 * list_cut_position - cut a list into two
 * @new_list: a new list to add all removed entries
 * @old_list: a list with entries
 * @entry: an entry within head, could be the head itself
 *	and if so we won't cut the list
 *
 * This helper moves the initial part of @head, up to and
 * including @entry, from @head to @list. You should
 * pass on @entry an element you know is on @head. @list
 * should be an empty list or a list you do not care about
 * losing its data.
 *
 */
static inline void dlist_cut_position(
	dlist_t *old_list, 
	dnode_t *entry, 
	dlist_t *new_list)
{
	if (dlist_empty(old_list))
		return;
	if (dlist_is_singular(old_list) &&
		(old_list->next != entry && 
		old_list != entry)) {
		return;
	}
	if (entry == old_list)
		dlist_init(new_list);
	else
		__list_cut_position(new_list, old_list, entry);
}

static inline void __list_splice(
	const dlist_t *list,
	dnode_t *prev,
	dnode_t *next)
{
	dnode_t *first = list->next;
	dnode_t *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

/**
 * list_splice - join two lists, this is designed for stacks
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void dlist_join(const dlist_t *add, dlist_t *to)
{
	if (!dlist_empty(add))
		__list_splice(add, to, to->next);
}

/**
 * list_splice_tail - join two lists, each list being a queue
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void dlist_join_tail(dlist_t *add, dlist_t *to)
{
	if (!dlist_empty(add))
		__list_splice(add, to->prev, to);
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define dlist_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define dlist_first_entry(ptr, type, member) \
	dlist_entry((ptr)->next, type, member)

#define dlist_next_entry(ptr, head, type, member) \
	(head) == (ptr)->member.next? NULL: \
	dlist_entry((ptr)->member.next, type, member)

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define dlist_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * __list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 *
 * This variant doesn't differ from list_for_each() any more.
 * We don't do prefetching in either case.
 */
#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define dlist_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define dlist_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define dlist_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define dlist_for_each_entry(pos, head, type, member)				\
	for (pos = dlist_entry((head)->next, type, member);	\
	     &pos->member != (head); 	\
	     pos = dlist_entry(pos->member.next, type, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define dlist_for_each_entry_reverse(pos, head, type, member)			\
	for (pos = dlist_entry((head)->prev, type, member);	\
	     &pos->member != (head); 	\
	     pos = dlist_entry(pos->member.prev, type, member))

/**
 * list_prepare_entry - prepare a pos entry for use in list_for_each_entry_continue()
 * @pos:	the type * to use as a start point
 * @head:	the head of the list
 * @member:	the name of the list_struct within the struct.
 *
 * Prepares a pos entry for use as a start point in list_for_each_entry_continue().
 */
#define dlist_prepare_entry(pos, head, type, member) \
	((pos) ? : dlist_entry(head, type, member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define dlist_for_each_entry_continue(pos, head, type, member) 		\
	for (pos = dlist_entry(pos->member.next, type, member);	\
	     &pos->member != (head);	\
	     pos = dlist_entry(pos->member.next, type, member))

/**
 * list_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Start to iterate over list of given type backwards, continuing after
 * the current position.
 */
#define dlist_for_each_entry_continue_reverse(pos, head, type, member)		\
	for (pos = dlist_entry(pos->member.prev, type, member);	\
	     &pos->member != (head);	\
	     pos = dlist_entry(pos->member.prev, type, member))

/**
 * list_for_each_entry_from - iterate over list of given type from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define dlist_for_each_entry_from(pos, head, type, member) 			\
	for (; &pos->member != (head);	\
	     pos = dlist_entry(pos->member.next, type, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define dlist_for_each_entry_safe(pos, n, head, type, member)			\
	for (pos = dlist_entry((head)->next, type, member),	\
		n = dlist_entry(pos->member.next, type, member);	\
	     &pos->member != (head); 					\
	     pos = n, n = dlist_entry(n->member.next, type, member))

/**
 * list_for_each_entry_safe_continue - continue list iteration safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type, continuing after current point,
 * safe against removal of list entry.
 */
#define dlist_for_each_entry_safe_continue(pos, n, head, type, member) 		\
	for (pos = dlist_entry(pos->member.next, type, member), 		\
		n = dlist_entry(pos->member.next, type, member);		\
	     &pos->member != (head);						\
	     pos = n, n = dlist_entry(n->member.next, type, member))

/**
 * list_for_each_entry_safe_from - iterate over list from current point safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define dlist_for_each_entry_safe_from(pos, n, head, type, member) 			\
	for (n = dlist_entry(pos->member.next, type, member);		\
	     &pos->member != (head);						\
	     pos = n, n = dlist_entry(n->member.next, type, member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 *
 * Iterate backwards over list of given type, safe against removal
 * of list entry.
 */
#define dlist_for_each_entry_safe_reverse(pos, n, head, type, member)		\
	for (pos = dlist_entry((head)->prev, type, member),	\
		n = dlist_entry(pos->member.prev, type, member);	\
	     &pos->member != (head); 					\
	     pos = n, n = dlist_entry(n->member.prev, type, member))

/**
 * list_safe_reset_next - reset a stale list_for_each_entry_safe loop
 * @pos:	the loop cursor used in the list_for_each_entry_safe loop
 * @n:		temporary storage used in list_for_each_entry_safe
 * @member:	the name of the list_struct within the struct.
 *
 * list_safe_reset_next is not safe to use in general if the list may be
 * modified concurrently (eg. the lock is dropped in the loop body). An
 * exception to this is if the cursor element (pos) is pinned in the list,
 * and list_safe_reset_next is called after re-taking the lock and before
 * completing the current iteration of the loop body.
 */
#define dlist_safe_reset_next(pos, n, type, member)				\
	n = dlist_entry(pos->member.next, type, member)


#endif /*_DLIST_H_KIMZHANG*/
