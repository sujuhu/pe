/*
Copyright(c) 2011. Kim Zhang [analyst004 at gmail.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/
#ifndef LIB_PE_H_
#define LIB_PE_H_

#include "imgfmt.h"
#ifdef __cplusplus
extern "C" {
#endif

#define LIBPE_VERSION "0.3.0"
#define LIBPE_VERNUM 0x0300
#define LIBPE_VER_MAJOR 0
#define LIBPE_VER_MINOR 3
#define LIBPE_VER_REVISION 0
#define LIBPE_VER_SUBREVISION 0


#ifndef ECANCELED
#define ECANCELED   401
#endif

typedef unsigned int rva_t;
typedef unsigned int raw_t;
typedef unsigned int va_t;

#define GET_DOS_HEADER( s )  ((IMAGE_DOS_HEADER*)s)

#define GET_NT_HEADER( s )   \
  ((IMAGE_NT_HEADERS*)((const char*)(s)+GET_DOS_HEADER(s)->e_lfanew ))

#define GET_SECTION_HEADER(nt, i) \
  ((IMAGE_SECTION_HEADER*)((char*)nt + sizeof(int) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader+(i)*sizeof(IMAGE_SECTION_HEADER)))

//获取基地址
#define GET_IMAGE_BASE( s ) \
 (unsigned int)(/*1*/(/*2*/(IMAGE_NT_HEADERS*)((const char*)s + ((IMAGE_DOS_HEADER*)s)->e_lfanew) /*2*/ )->OptionalHeader.ImageBase/*1*/)

#define INVALID_FILE_OFFSET -1

#define INVALID_VIRTUAL_ADDRESS -1

//导出函数
typedef struct _EXPORT_FUNCTION
{
  int   Ordinal;                //函数序号
  char  FunctionName[256];      //函数名称
  va_t  FunctionVirtualAddress; //函数内存地址
}EXPORT_FUNCTION, *PEXPORT_FUNCTION;

//导入函数
typedef struct _IMPORT_FUNCTION
{
  //int IndexOfModule;
  //uint32_t IndexInModule;   //在该导入模块中第几个导入函数
  union {
    unsigned short FunctionOrdinal; //以序号的方式导入函数时有效
    unsigned short FunctionHint;    //以名称的方式导入函数时有效
  };
  char FunctionName[256];     //以名称的方式导入函数
  raw_t ThunkOffset;
  rva_t ThunkRVA;
  unsigned int ThunkValue;    //最高位1， 表示序号方式导入， 无函数名称
  raw_t OffsetName;
  rva_t iat;                  //导入函数地址实际填入的位置
}IMPORT_FUNCTION, *PIMPORT_FUNCTION;

//导入模块
typedef struct _IMPORT_MODULE
{
  char  ModuleName[260];      //模块名称
  rva_t OriginalFirstThunk;
  unsigned int TimeDataStamp;
  rva_t ForwarderChain;
  rva_t FirstThunk;
  raw_t OffsetName;           //模块名称的位置
}IMPORT_MODULE, *PIMPORT_MODULE;

//资源ID
typedef struct _PE_RESOURCE_ID
{
  wchar_t ResourceName[64];   //资源名称
  unsigned short  ResourceID; //资源ID
  int   OffsetToData;         //数据偏移
  int   Size;                 //数据大小
  unsigned int  CodePage;     //代码页
  _PE_RESOURCE_ID*    Next;
}PE_RESOURCE_ID, *PPE_RESOURCE_ID;

//资源类型
typedef struct _PE_RESOURCE_TYPE
{
  wchar_t ResourceTypeName[64];   //资源类型名称
  unsigned int ResourceTypeID;      //资源类型ID/资源名称Offset
  PPE_RESOURCE_ID ResourceList;   //资源列表
}PE_RESOURCE_TYPE, *PPE_RESOURCE_TYPE;

/*
 * Description: 枚举导入模块回调函数
 * Parameter:   pImportModule    导入模块相关信息
 *              lpParam          回调参数
 * Return:      true    继续枚举
 *              false   停止枚举
 */
typedef
bool (*fnEnumImportModuleCallback)(
    IMPORT_MODULE* pImportModule,
    void* lpParam );

/*
 * Description: 枚举导入函数回调函数
 * Parameter:   pImportFunction  导入函数相关信息
 *              pImportModule    导入模块相关信息
 *              lpParam          回调参数
 * Return:      true    继续枚举
 *              false   停止枚举
 */
typedef bool (*fnEnumImportFunctionCallback)(
    PIMPORT_FUNCTION pImportFunction,
    PIMPORT_MODULE pImportModule,
    void* lpParam );

/*
 * Description: 判断是否PE文件
 * Parameter:   lpszFile  文件全路径
 * Return:      TRUE    是PE文件
 *              FALSE   不是PE文件
 */
int IsValidPE(
    const char* stream,
    size_t stream_size);


/*
 * Description: 根据虚拟地址计算文件偏移地址
 * Parameter:   lpFileData  文件数据
 * Return:      INVALID_FILE_OFFSET   计算失败
 *            否则， 返回文件偏移地址的值
 */
raw_t RvaToRaw(
    const char *stream,
    size_t stream_size,
    rva_t rva);

/*
 * Description: 根据文件偏移地址计算虚拟地址
 * Parameter: stream  文件数据
 *            raw 文件偏移地址
 * Return:    INVALID_VIRTUAL_ADDRESS 计算失败
 *          否则， 返回虚拟地址的值
 */
rva_t RawToRva(
    const char* stream,
    raw_t raw);

/*
 * Description: 枚举导出函数
 * Parameter: lpFileData  文件数据
 *            cbFileSize  文件长度
 * pFunctions 导出函数数据
 *  pcbSize   数据缓冲区长度
 * Return:    true    枚举成功
 *            false   枚举失败
 */
bool EnumExportFunction(
    const char* stream,
    size_t stream_size,
    EXPORT_FUNCTION *exports,
    size_t* bufsize);

/*
 * Description: 枚举导入模块和函数
 * Parameter: lpFileData    文件数据
 *            cbFileSize    文件数据大小
 *            pfnModule   导入模块枚举函数
 *            lpParamModule 导入模块枚举回调函数参数
 *            pfnFunction   导入函数枚举回调函数
 *            lpParamFunction 导入函数枚举回调函数参数
 * Return:    true      枚举成功
 *            false     枚举失败， GetLastError()
  */
bool EnumImportModuleAndFunction(
    const char* stream,
    size_t stream_size,
    fnEnumImportModuleCallback module_routine,
    void* module_param,
    fnEnumImportFunctionCallback api_routine,
    void* api_param);

/*
 * Description: 获取导入模块数量
 * Parameter:   lpFileData      文件数据
 *      cbFileSize      文件数据大小
 * Return:      导入模块数量
 */
int  GetImportModuleCount(
    const char* stream,
    size_t stream_size);

/*
 * Description: 计算虚拟地址所在的节
 * Parameter:   lpFileData      文件数据
 *        dwVirtualAddress  虚拟地址
 * Return:      节段索引值
 */
int GetSectionIndexByRva(
    const char* stream,
    rva_t rva);

/*
 * Description: 获取导出DLL名称
 * Parameter:   lpFileData    文件数据
 *        cbFileSize    文件大小
 *        DllName     输出缓冲区
 *        BufSize     缓冲区大小
 * Return:      TRUE      成功
 */
bool GetExportDllName(
    const char *stream,
    size_t stream_size,
    char *dll_name,
    size_t bufsize);

/*
 * Description: 计算文件偏移所在的节
 * Parameter: lpFileData      文件数据
 * dwFileOffset   文件偏移值
 * Return:    节段索引值
 */
int  GetSectionIndexByRaw(
    const char* stream,
    raw_t raw);

typedef
bool (*RESOURCE_CALLBACK)(
    wchar_t* wName,
    unsigned short NameLen,
    IMAGE_RESOURCE_DATA_ENTRY* DataEntry,
    void* lpParam );

/*
 * Description: 枚举资源
 * Parameter: lpFileData    文件数据
 *            cbFileSize    文件数据大小
 *            pResources    资源类型数组
 *            pcbSize     资源类型数组长度
 * Return:    true  枚举成功
 *            false 枚举失败， errno
 */
bool EnumResource(
    const char* stream,
    size_t stream_size,
    RESOURCE_CALLBACK pfnRoutine,
    void* lpParam);

typedef struct _PE_RELOCATION_ITEM
{
  rva_t rva;
  int   Type;
}PE_RELOCATION_ITEM, *PPE_RELOCATION_ITEM;

typedef
bool (*RELOC_ITEM_CALLBACK)(
    rva_t rvaOwnerBlock,
    PPE_RELOCATION_ITEM pItem,
    void* lpParam );

typedef struct _PE_RELOCATION_BLOCK
{
    rva_t rva;  //重定位块的相对偏移地址
    int cItem;  //重定位项的数量
}PE_RELOCATION_BLOCK, *PPE_RELOCATION_BLOCK;

typedef
bool (*RELOC_BLOCK_CALLBACK)(
    PPE_RELOCATION_BLOCK pBlock,
    void* lpParam );

/*
 * Description: 枚举重定位数据
 * Parameter: lpFileData    文件数据
 *            cbFileSize    文件数据大小
 *            pfnBlock    重定位块枚举回调函数
 *            lpBlockParam  重定位块枚举回调函数参数
 *            pfnItem     重定位项回调函数
 *            lpItemParam   重定位项回调函数参数
 * Return:    true      枚举成功
 *            false     枚举失败, GetLastError()
 */
bool EnumRelocation(
    const char* stream,
    size_t stream_size,
    RELOC_BLOCK_CALLBACK block_routine,
    void* lpBlockParam,
    RELOC_ITEM_CALLBACK item_routine,
    void* lpItemParam );

typedef struct _PE_BOUND
{
    int   TimeDateStamp;
    char  ModuleName[128];
    unsigned short    NumberOfModuleForwarderRefs;
}PE_BOUND, *PPE_BOUND;

/*
 * Description: 枚举Bound
 * Parameter: stream        文件数据
 *            stream_size   文件数据大小
 *            pBounds       Bound数组
 *            pcbSize       Boudn数组长度
 * Return:    true  枚举成功
 *            false 枚举失败， GetLastError()
 */
bool EnumBound(
    const char* stream,
    size_t stream_size,
    PPE_BOUND pBounds,
    size_t* pcbSize);

/*
 * Description: 获取节段头部信息
 * Parameter: lpFileData  文件数据
 *            nIndexOfSection   节段索引号
 *            pSection      节段信息内容
 * Return:    true    获取成功
 *            false   获取失败， GetLastError()
 */
bool GetSectionHeader(
    const char* stream,
    int section_index,
    IMAGE_SECTION_HEADER *section_header);

/*
 * Description: 获取附加数据的开始位置和长度
 * Parameter: stream    文件数据
 *            stream_size   文件数据长度
 *            overlay_raw     附加数据开始位置
 *            overlay_len     附加数据长度
 * Return:    true      获取成功
 *            false     获取失败， GetLastError()
 */
bool GetOverlay(
    const char* stream,
    size_t stream_size,
    raw_t* overlay_raw,
    size_t* overlay_len);


/*
 * Description: 获取图标数据的开始位置和长度
 * Parameter: stream    文件数据
 *            stream_size   文件数据长度
 *            ico_file      输出的ico文件全路径
 * Return:    true      获取成功
 *            false     获取失败， GetLastError()
 */
bool GetIcon(
    const char* stream,
    size_t stream_size,
    const char* ico_file);

//PE间隙描述符
typedef struct _SECTION_GAP
{
  raw_t offset;   //间隙在文件中的偏移
  int length;   //间隙的长度
}SECTION_GAP, *PSECTION_GAP;

/*
 * Description: 获取附加数据的开始位置和长度
 * Parameter: stream    文件数据
 *            stream_size   文件数据长度
 *            pSectionGaps  间隙描述符数组
 *            cbSize      数组长度
 * Return:    间隙描述符的长度
 */
int EnumSectionGap(
    const char* stream,
    size_t stream_size,
    SECTION_GAP* pSectionGaps,
    size_t cbSize);





//Notice: Not Support MultiThread
//Notice: Not Support Unicode

typedef struct _PE_VERSION
{
  char FileVersion[128];            //文件版本
  char CompanyName[256];            //公司名称
  char FileDescription[256];          //文件描述
  char ProductName[256];            //产品名称
  char LegalCopyright[256];         //版权信息
  char InternalName[128];           //内部名称
  char Comments[256];             //备注信息
  char SpecialBuild[128];           //特殊内部版本
  char LegalTrademarks[128];          //合法商标
  char PrivateBuild[128];           //个人用内部版本
  char ProductVersion[128];         //产品版本
  char OriginalFilename[128];         //原始文件名
  wchar_t wLanguage;
  wchar_t wCodePage;
}PE_VERSION;

/*
 * Description: 获取PE文件版本信息
 * Parameter: stream    文件数据
 *            stream_size   文件数据长度
 *            verinfo       PE版本信息
 * Return:    间隙描述符的长度
 */
bool GetVersionInfo(
    const char* filename,
    PE_VERSION *verinfo);


/*
 * Description: 将PE文件加载到内存中
 * Parameter: stream        文件数据
 *            stream_size   文件数据长度
 *            image         加载到内存中地址
 *            image_size    内存缓冲区地址
 * Return:    间隙描述符的长度
 */
bool LoadPEImage(
    const char* stream, 
    size_t stream_size, 
    char* image, 
    size_t image_size);


typedef struct _ver_info
{ 
  wchar_t name[128];
  wchar_t value[512];
}ver_info_t;


#define version_t   void*

void* PEOpenVersion(const char* version, size_t versize);

bool PENextVersion(void* ver_handle, ver_info_t* verinfo);

void PECloseVersion(void* ver_handle);


#ifdef __cplusplus
}
#endif

#endif      /* LIB_PE_H_ */
