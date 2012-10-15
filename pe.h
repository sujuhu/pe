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

typedef uint32_t rva_t;
typedef uint32_t raw_t;
typedef uint32_t va_t;
typedef int      pehandle_t;

#define GET_DOS_HEADER( s )  ((IMAGE_DOS_HEADER*)s)

#define GET_NT_HEADER( s )   \
  ((IMAGE_NT_HEADERS*)((const char*)(s)+GET_DOS_HEADER(s)->e_lfanew ))

#define GET_SECTION_HEADER(nt, i) \
  ((IMAGE_SECTION_HEADER*)((char*)nt + sizeof(int) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader+(i)*sizeof(IMAGE_SECTION_HEADER)))

//获取基地址
#define GET_IMAGE_BASE( s ) \
 (unsigned int)(/*1*/(/*2*/(IMAGE_NT_HEADERS*)((const char*)s + ((IMAGE_DOS_HEADER*)s)->e_lfanew) /*2*/ )->OptionalHeader.ImageBase/*1*/)

#define INVALID_PE              -1

#define INVALID_FILE_OFFSET     -1

#define INVALID_VIRTUAL_ADDRESS -1

//导出函数

typedef struct _pe_resource_t
{
  bool      is_directory;
  wchar_t   ResourceName[64];   //资源名称
  uint16_t  ResourceID; //资源ID
  int32_t   OffsetToData;         //数据偏移
  int32_t   Size;                 //数据大小
  uint32_t  CodePage;     //代码页
}pe_resource_t;

/**
 * Description: parse pe format
 * Parameter:   stream      
 *              size           
 * Return:      INVALID_PE     parse pe fail, errno
 *              
 */
int   pe_open(const char* stream, size_t size);

/**
 * Description: clean and close pe format
 * Parameter:   fd        pe descriptor, return by pe_open()          
 * Return:      void
 *              
 */
void  pe_close(int  fd);

/*
 * Description: 根据虚拟地址计算文件偏移地址
 * Parameter:   lpFileData  文件数据
 * Return:      INVALID_FILE_OFFSET   计算失败
 *            否则， 返回文件偏移地址的值
 */
raw_t rva_to_raw(int fd, rva_t rva);

/*
 * Description: 根据文件偏移地址计算虚拟地址
 * Parameter: stream  文件数据
 *            raw 文件偏移地址
 * Return:    INVALID_VIRTUAL_ADDRESS 计算失败
 *          否则， 返回虚拟地址的值
 */
rva_t raw_to_rva(int fd, rva_t raw);

/*
 * 获取PE格式附加数据相关的信息
 */
IMAGE_OVERLAY* pe_overlay(int fd);


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
  raw_t   offset;   //间隙在文件中的偏移
  int32_t length;   //间隙的长度
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


#ifdef __cplusplus
}
#endif

#endif      /* LIB_PE_H_ */
