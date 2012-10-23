#ifndef STRUCT_AVL_H_
#define STRUCT_AVL_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ERRCODE_DEFINED
#define _ERRCODE_DEFINED
typedef int errno_t;
#endif

typedef struct _avltree_t
{
	uint32_t min_key;
	uint32_t max_key;
	struct _avltree_t* left;		//左子树
	struct _avltree_t* right;		//右子树
	struct _avltree_t* parent;		//父节点
	int		height;					//树的高度
	int 	balance_factor;				//平衡因子 = 左子树的高度 - 右子树的高度
	int 	data_len;
	char* 	data;
}avltree_t;


/* 插入AVL树 */
errno_t InsertAvlEntry(
	avltree_t* tree, 
	uint32_t min_key,
	uint32_t max_key,
	char* data, 
	int data_len, 
	avltree_t** new_root);

avltree_t* GetMinAvlEntry(avltree_t* tree);

avltree_t* GetMaxAvlEntry(avltree_t* tree);

avltree_t* FindAvlEntry(avltree_t* tree, uint32_t key);

errno_t RemoveAvlEntry(
	avltree_t* tree, 
	uint32_t min_key, 
	avltree_t* new_root);

/* 清空AVL数 */
void ClearAvlTree(avltree_t* tree);

errno_t LoadAvlTree(
	avltree_t* tree, 
	FILE* file, 
	int32_t size, 
	avltree_t** new_root);

errno_t SaveAvlTree(avltree_t* tree, FILE* file, int32_t* size);

#ifdef __cplusplus
}
#endif


#endif