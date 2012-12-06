#ifndef _HLIST_H_KIMZHANG
#define _HLIST_H_KIMZHANG
/*
 * Double linked lists with a single pointer list head.
 * Mostly useful for hash tables where the two pointer list head is
 * too wasteful.
 * You lose the ability to access the tail in O(1).
 */

typedef struct hlist_head {
	struct hlist_node *first;
}hlist_t;

typedef struct hlist_node {
	struct hlist_node *next, **pprev;
}hnode_t;

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) hlist_t name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

static inline void INIT_HLIST_NODE(hnode_t *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline int hlist_unhashed(const hnode_t *h)
{
	return !h->pprev;
}

static inline int hlist_empty(const hlist_t *h)
{
	return !h->first;
}

static inline void __hlist_del(hnode_t *n)
{
	hnode_t *next = n->next;
	hnode_t **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(hnode_t *n)
{
	__hlist_del(n);
	n->next = n; /*LIST_POISON1;*/
	n->pprev = &n; /* LIST_POISON2;*/
}

static inline void hlist_del_init(hnode_t *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

static inline void hlist_add_head(hnode_t *n, hlist_t *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

/* next must be != NULL */
static inline void hlist_add_before(hnode_t *n, hnode_t *next)
{
	n->pprev = next->pprev;
	n->next = next;
	next->pprev = &n->next;
	*(n->pprev) = n;
}

static inline void hlist_add_after(hnode_t *n, hnode_t *next)
{
	next->next = n->next;
	n->next = next;
	next->pprev = &n->next;

	if(next->next)
		next->next->pprev  = &next->next;
}

/* after that we'll appear to be on some hlist and hlist_del will work */
static inline void hlist_add_fake(hnode_t *n)
{
	n->pprev = &n->next;
}

/*
 * Move a list from one list head to another. Fixup the pprev
 * reference of the first entry if it exists.
 */
static inline void hlist_move_list(hlist_t *old, hlist_t *to)
{
	to->first = old->first;
	if (to->first)
		to->first->pprev = &to->first;
	old->first = NULL;
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos &&							 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_for_each_entry_continue - iterate over a hlist continuing after current point
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue(tpos, pos, member)		 \
	for (pos = (pos)->next;						 \
	     pos &&							 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_for_each_entry_from - iterate over a hlist continuing from current point
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos &&							 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

/**
 * hlist_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @n:		another &struct hlist_node to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
/*
#define hlist_for_each_entry_safe(tpos, pos, n, head, type, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_entry(pos, type, member); 1;}); \
	     pos = n)
*/
#define hlist_for_each_entry_safe(pos, head, type, member) 	\
	for (hnode_t *c = (head)->first, *n = NULL;		\
	     c && \
	     ((n = c->next) == NULL || n != NULL) && \
	     ((pos) = hlist_entry(c, type, member)) != NULL;	\
	     c = n)

#define INIT_HASH_TABLE(name, size)	\
	hlist_t	name[size]; for (int i=0; i<size; i++) INIT_HLIST_HEAD(&name[i]);

#define HTABLE_INDEX(h, s) ((h) & (s-1))

static inline
hlist_t* htable_burket(hlist_t* table, int burk_size, uint32_t hash)
{
	return &table[HTABLE_INDEX(hash, burk_size)];
}

#endif /*_HLIST_H_KIMZHANG*/