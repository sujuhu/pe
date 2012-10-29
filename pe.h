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

#include "petype.h"
#include "peformat.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ECANCELED
#define ECANCELED   401
#endif

typedef uint32_t rva_t;
typedef uint32_t raw_t;
typedef uint32_t va_t;

#define INVALID_PE       (int)0

#define INVALID_RAW     (raw_t)-1

#define INVALID_RVA     (raw_t)-1

#define INVALID_SECTION_ID  (raw_t)-1

#define IS_RESOURCE_DIRECTORY(entry)  entry->DataIsDirectory

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


IMAGE_NT_HEADERS*  pe_nt_header(int fd);


IMAGE_DOS_HEADER* pe_dos_header(int fd);

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


IMAGE_EXPORT_FUNCTION *pe_export_first(int fd);


IMAGE_EXPORT_FUNCTION *pe_export_next(IMAGE_EXPORT_FUNCTION* iter);

const char* pe_export_dllname(int fd);

bool pe_import_dllname(
    int fd, 
    IMAGE_IMPORT_DESCRIPTOR* import_dll,
    char* dllname, 
    int name_len);

IMAGE_IMPORT_DESCRIPTOR* pe_import_dll_first(int fd);

IMAGE_IMPORT_DESCRIPTOR* pe_import_dll_next(IMAGE_IMPORT_DESCRIPTOR* iter);

IMAGE_IMPORT_FUNCTION* pe_import_api_first(IMAGE_IMPORT_DESCRIPTOR* import_dll);

IMAGE_IMPORT_FUNCTION* pe_import_api_next(IMAGE_IMPORT_FUNCTION* iter);

IMAGE_RESOURCE_DATA_ENTRY* pe_resource_data(
      int fd, 
    IMAGE_RESOURCE_DIRECTORY_ENTRY* entry);

IMAGE_RELOCATION_ITEM* pe_reloc_first(int fd);

IMAGE_RELOCATION_ITEM* pe_reloc_next(IMAGE_RELOCATION_ITEM* iter);

const char* pe_bound_import_dllname(int fd, IMAGE_BOUND_IMPORT_DESCRIPTOR* dll);

IMAGE_BOUND_IMPORT_DESCRIPTOR* pe_bound_import_first(int fd);

IMAGE_BOUND_IMPORT_DESCRIPTOR* pe_bound_import_next(
    IMAGE_BOUND_IMPORT_DESCRIPTOR* iter);

int pe_section_by_rva(int fd, rva_t rva);

int  pe_section_by_raw(int fd, raw_t raw);

bool pe_icon_file(int fd, const char* ico_file);

IMAGE_VERSION* pe_version_first(int fd);

IMAGE_VERSION* pe_version_next(IMAGE_VERSION* iter);

bool pe_remove_last_section(int fd);

IMAGE_RESOURCE_DIRECTORY_ENTRY* pe_resource_first(
    int fd,
    IMAGE_RESOURCE_DIRECTORY_ENTRY* parent);

IMAGE_RESOURCE_DIRECTORY_ENTRY* pe_resource_next(
  IMAGE_RESOURCE_DIRECTORY_ENTRY* prev);

bool pe_resource_name(int fd,  IMAGE_RESOURCE_DIRECTORY_ENTRY* res,
    char* name, int max_len);

IMAGE_RESOURCE_DIRECTORY_ENTRY* pe_resource_first(
    int fd,
    IMAGE_RESOURCE_DIRECTORY_ENTRY* parent);

IMAGE_RESOURCE_DIRECTORY_ENTRY* pe_resource_next(
  IMAGE_RESOURCE_DIRECTORY_ENTRY* prev);

bool copy_section_header(int fd,int sect_id, IMAGE_SECTION_HEADER *sect_header);

IMAGE_SECTION_HEADER* pe_section_header(int fd, int sect_id);

uint8_t* pe_stream_by_raw(int fd, raw_t raw);

uint8_t* pe_stream_by_rva(int fd, rva_t rva);

#ifdef __cplusplus
}
#endif

#endif      /* LIB_PE_H_ */
