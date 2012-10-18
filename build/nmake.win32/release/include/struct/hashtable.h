/*
	1.0	创建
	2.0	更改了接口， 使得枚举节点的时候可以删除节点
  	2.1 修正了关闭Zipper的时候内存泄露的问题
  	3.0 增加了节点父子关系的特性
  	3.1 基本数据类型使用C99规范
  	3.2 增加了序列化存储功能
 */
#ifndef HASH_TABLE_H_
#define HASH_TABLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ERRCODE_DEFINED
#define _ERRCODE_DEFINED
typedef int errno_t;
#endif

typedef struct _listentry_t {
	struct _listentry_t *Flink;
	struct _listentry_t *Blink;
}listentry_t;

//拉链的结构
typedef struct _hashtable_t
{
	int32_t		 NumberOfBurkets;	//拉链的长度
	int32_t		 NumberOfNode;		//节点总数
	listentry_t	 FastList;		//节点快速枚举链表
	listentry_t*	 HashTable;		//拉链
}hashtable_t;

#define ENUM_STOP	0
#define	ENUM_CONTINUE	1
#define ENUM_DELETE	2

/*
	拉链节点枚举回调函数
	返回值:		ENUM_STOP		继续枚举
			ENUM_CONTINUE		停止枚举
			ENUM_DELETE		删除该节点
	备注:	在枚举回调函数中不能释放缓冲区
*/
typedef int (*ENUM_ZIPNODE_ROUTINE)( 
	uint32_t idNode, 
	uint8_t* pNodeData, 
	size_t	 DataSize,
	void* Context );

//创建HASH表
errno_t CreateHashTable(
	uint32_t table_length,  
	hashtable_t** hash_table);

//插入节点
errno_t InsertHashEntry(
	hashtable_t* table, 
	uint32_t idNode, 
	uint8_t* NodeData, 
	size_t DataSize );

//在拉链中查找节点
uint8_t*  FindHashEntry(
	hashtable_t* table, 
	uint32_t idNode,
	uint32_t* data_size = NULL );

//将节点从拉链中移除（ 并没有销毁）
errno_t RemoveHashEntry( 
	hashtable_t* table, 
	uint32_t idNode );

//枚举拉链中的每个节点
errno_t EnumHashEntry(
	hashtable_t* table, 
	ENUM_ZIPNODE_ROUTINE EnumRoutine, 
	void* Context );

//清除所有的节点
errno_t	ClearHashTable( 
	hashtable_t* table );

//获取节点总数
uint32_t GetHashEntryCount( 
	hashtable_t* table );

//为两个节点建立父子关系
errno_t AddChildHashEntry(
    hashtable_t* table,
    uint32_t idParentNode,
    uint32_t idChildNode);

//解除两个节点之间的父子关系
errno_t RemoveChildHashEntry(
    hashtable_t* table,
    uint32_t idParentNode,
    uint32_t idChildNode);

//获取指定节点下子节点的数量
int GetChildHashEntryCount(
	hashtable_t* table, 
	uint32_t idNode);

//关闭拉链结构
void	CloseHashTable(
	hashtable_t* table );

//保存拉链数据
errno_t SaveHashTable(
	hashtable_t* table, 
	FILE* file, 
	int32_t* size);

//加载拉链数据
errno_t LoadHashTable(
	hashtable_t* table, 
	FILE* file, 
	int32_t size);

#ifdef __cplusplus
}
#endif

#endif