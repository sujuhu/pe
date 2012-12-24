/*
Copyright(c) 2011. Kim Zhang[analyst004@gmail.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/
#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif
#undef __STRICT_ANSI__ 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <assert.h>
#include <strconv.h>
#include "petype.h"
#include <locale.h>

#include <slist.h>
#include <filemap.h>
#include "petype.h"
#include "peformat.h"
#include "verfmt.h"
#include "pe.h"

#ifdef __GNUC__
#ifdef __MINGW32__

#else
//linux or linux
#define _snprintf snprintf
#define _snwprintf swprintf
#endif
#endif

//用于字节边界对齐
#define ALIGN(o,a)  (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))

/*
* IS_CONTAINED(buf1, size1, buf2, size2) checks ifbuf2 is contained
* within buf1.
*
* buf1 and buf2 are pointers (or offsets) for the main buffer and the
* sub-buffer respectively, and size1/2 are their sizes
*
* The macro can be used to protect against wraps.
*/

#define IS_CONTAINED(bb, bb_size, sb, sb_size)  \
  (bb_size > 0 && sb_size > 0 && sb_size <= bb_size \
  && sb >= bb && sb + sb_size <= bb + bb_size)

#define DIRECTORY_ENTRY(s, i) \
  (&(GET_NT_HEADER(s)->OptionalHeader.DataDirectory[i]))


#define GET_DOS_HEADER( s )  ((IMAGE_DOS_HEADER*)s)

#define GET_NT_HEADER( s )   \
  ((IMAGE_NT_HEADERS32*)((const char*)(s)+GET_DOS_HEADER(s)->e_lfanew ))

#define GET_SECTION_HEADER(nt, i) \
  ((IMAGE_SECTION_HEADER*)((char*)nt + sizeof(int) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader+(i)*sizeof(IMAGE_SECTION_HEADER)))

//获取基地址
#define GET_IMAGE_BASE( s ) \
 (unsigned int)(/*1*/(/*2*/(IMAGE_NT_HEADERS32*)((const char*)s + ((IMAGE_DOS_HEADER*)s)->e_lfanew) /*2*/ )->OptionalHeader.ImageBase/*1*/)


typedef struct _pe_t{
  IMAGE_DOS_HEADER* dos;   //dos header
  IMAGE_NT_HEADERS32*  nt;    //nt header
  const char* stream;
  size_t      size;
  const char* dll_name;     //export dll name
  slist_t     export_apis;
  slist_t import_dlls;
  slist_t version;
  slist_t reloc_list;
  slist_t resource;
  slist_t bound_list;
  slist_t gap_list;
  slist_t section_list;
  bool  open_by_file;
  MAPPED_FILE view;
  IMAGE_OVERLAY   overlay;
}pe_t;

typedef struct _export_api_t{
    IMAGE_EXPORT_FUNCTION data;
    snode_t node;
}export_api_t;

//导入函数
typedef struct _import_api_t {
  IMAGE_IMPORT_FUNCTION data;
  snode_t node;
}import_api_t;

//导入模块
typedef struct _import_dll_t{
  IMAGE_IMPORT_DESCRIPTOR   data;
  slist_t api_list;
  snode_t node;
}import_dll_t;

typedef struct _version_t{
  IMAGE_VERSION data;
  snode_t node;
}version_t;

typedef struct _reloc_t{
  IMAGE_RELOCATION_ITEM   data;
  snode_t node;
}reloc_t;

typedef struct _resource_t{
  IMAGE_RESOURCE_DIRECTORY_ENTRY data;
  snode_t node;
  slist_t child;
}resource_t;

typedef struct _bound_t{
  IMAGE_BOUND_IMPORT_DESCRIPTOR data;
  snode_t node;
}bound_t;

typedef struct _gap_t{
  IMAGE_GAP data;
  snode_t node;
}gap_t;

typedef struct _section_t{
  IMAGE_SECTION_HEADER data;
  snode_t node;
}section_t;

bool parse_section(int fd);

bool parse_export(int fd);

bool parse_import(int fd);

bool parse_reloc(int fd);

bool parse_version(int fd);

bool parse_overlay(int fd);

bool parse_resource(int fd);

bool parse_bound(int fd);

bool parse_gap(pe_t* pe);

bool pe_init(pe_t* pe, const char* stream, int size)
{
  pe->stream = stream;
  pe->size = size;

  pe->dos = GET_DOS_HEADER(stream);
  pe->nt  = GET_NT_HEADER(stream);

  //读取PE头部数据
  if (pe->dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }

  if ((size_t)pe->dos->e_lfanew >= (size_t)size)  {
    return false;
  }

  if (pe->nt->Signature != IMAGE_NT_SIGNATURE
   || pe->nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
   || pe->nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ) {
    return false;
  }

  parse_section((intptr_t)pe);

  parse_export((intptr_t)pe);

  parse_import((intptr_t)pe);

  parse_reloc((intptr_t)pe);

  parse_version((intptr_t)pe);

  parse_overlay((intptr_t)pe);

  parse_resource((intptr_t)pe);

  parse_bound((intptr_t)pe);

  parse_gap(pe);

  return true;
}

int  pe_open_file(const char* file)
{
  if (file == NULL) {
    errno = EINVAL;
    return INVALID_PE;
  }

  pe_t* pe = (pe_t*)malloc(sizeof(pe_t));
  if (pe == NULL) {
    return INVALID_PE;
  }
  memset((uint8_t*)pe, 0, sizeof(pe_t));

  if (0 != map_file(file, &pe->view)) {
    free(pe);
    pe = NULL;
    return INVALID_PE;
  }

  pe->open_by_file = true;

  if(!pe_init(pe, (const char*)pe->view.data, pe->view.size)) {
    free(pe);
    pe = NULL;
    return INVALID_PE;
  }

  return (intptr_t)pe; 
}

int  pe_open(const char* stream, size_t size)
{      
  if (stream==NULL || size == 0){
    errno = EINVAL;
    return INVALID_PE;
  }

  pe_t* pe = (pe_t*)malloc(sizeof(pe_t));
  if (pe==NULL) {
    return INVALID_PE;
  }
  memset(pe, 0, sizeof(pe_t));

  if (!pe_init(pe, stream, size)) {
    free(pe);
    pe = NULL;
    return INVALID_PE;
  }

  return (intptr_t)pe; 
}

int pe_size(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return -1;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return pe->size;
}

void clean_resource(slist_t* list)
{
  resource_t* res = NULL;
  slist_for_each_safe(res, list, resource_t, node) {
    if (!slist_empty(&res->child))
      clean_resource(&res->child);
    free(res);
    res = NULL;
  }
}

void  pe_close(int  fd)
{  
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  export_api_t* item = NULL;
  slist_for_each_safe(item, &pe->export_apis, export_api_t, node) {
    free(item);
    item = NULL;
  }

  import_dll_t* dll = NULL;
  slist_for_each_safe(dll, &pe->import_dlls, import_dll_t, node) {
    import_api_t* api = NULL;
    slist_for_each_safe(api, &dll->api_list, import_api_t, node) {
      free(api);
      api = NULL;
    }
    free(dll);
    dll = NULL;
  }

  version_t* ver = NULL;
  slist_for_each_safe(ver, &pe->version, version_t, node) {
    free(ver);
    ver = NULL;
  }

  bound_t* bound = NULL;
  slist_for_each_safe(bound, &pe->bound_list, bound_t, node) {
    free(bound);
    bound = NULL;
  }

  gap_t* gap = NULL;
  slist_for_each_safe(gap, &pe->gap_list, gap_t, node) {
    free(gap);
    gap = NULL;
  }

  reloc_t* reloc = NULL;
  slist_for_each_safe(reloc, &pe->reloc_list, reloc_t, node) {
    free(reloc);
    reloc = NULL;
  }

  clean_resource(&pe->resource);

  section_t* section = NULL;
  slist_for_each_safe(section, &pe->section_list, section_t, node) {
    free(section);
    section = NULL;
  }

  if (pe->open_by_file) {
    unmap_file(&pe->view);
    memset(&pe->view, 0, sizeof(MAPPED_FILE));
  }

  free(pe);
  pe = NULL;
} 

IMAGE_NT_HEADERS32*  pe_nt_header(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  return ((pe_t*)(intptr_t)fd)->nt;
}

IMAGE_DOS_HEADER* pe_dos_header(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  return ((pe_t*)(intptr_t)fd)->dos;
}

raw_t rva_to_raw(int fd, rva_t rva)
{
  if (fd == INVALID_PE || rva == INVALID_RVA) {
    errno = EINVAL;
    return INVALID_RAW;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  //枚举所有Section
  IMAGE_SECTION_HEADER *section = NULL;
  //uint32_t sectin_align_mask = pe->nt->OptionalHeader.SectionAlignment - 1;
  //uint32_t file_align = (uint32_t)pe->nt->OptionalHeader.FileAlignment;
  //uint32_t file_align_mask = file_align - 1;

  //计算rva在哪个节中
  raw_t raw = 0;
  for (size_t i=0; i < pe->nt->FileHeader.NumberOfSections; i++) {
    section = GET_SECTION_HEADER(pe->nt, i);
    if (rva >= section->VirtualAddress
     && rva <= (section->VirtualAddress + section->Misc.VirtualSize - 1)){
      raw = rva - section->VirtualAddress
                + section->PointerToRawData;
      goto ret;
    }
  }
  raw = rva;

ret:
  if (raw >= pe->size) {
    errno = ERANGE;
    return INVALID_RAW;
  }
  return raw;
}

rva_t raw_to_rva(int fd, raw_t raw)
{
  if (fd == INVALID_PE || raw == INVALID_RAW) {
    errno = EINVAL;
    return INVALID_RVA;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  for (size_t i=0; i < pe->nt->FileHeader.NumberOfSections; i++) {
    //判断FileOffset是否在该Section地址范围内
    IMAGE_SECTION_HEADER *section = GET_SECTION_HEADER(pe->nt, i);
    if (raw >= (raw_t)section->PointerToRawData
     && raw <= (raw_t)(section->PointerToRawData+section->SizeOfRawData-1)){
      //rva = File Offset + k.
      return raw + section->VirtualAddress - section->PointerToRawData;
    }
  }

  return INVALID_RVA;
}

uint8_t* pe_data_by_raw(int fd, raw_t raw)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  if (raw >= pe->size) {
    errno = ERANGE;
    return NULL;
  }
  return (uint8_t*)pe->stream + raw;
}

uint8_t* pe_data_by_rva(int fd, rva_t rva)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  raw_t raw = rva_to_raw(fd, rva);
  if (raw == INVALID_RAW) {
    return NULL;
  }

  return pe_data_by_raw(fd, raw);
}

/***********************************************************************
 *
 *  pe section
 *
 **********************************************************************/
bool parse_section(int fd)
{
  if (fd== INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  int count = pe->nt->FileHeader.NumberOfSections;
  for(int i=0; i<count; i++) {
    IMAGE_SECTION_HEADER* header = GET_SECTION_HEADER(pe->nt, i);
    section_t* section = (section_t*)malloc(sizeof(section_t));
    if (section == NULL) {
      return false;
    }
    memset(section, 0, sizeof(sizeof(section_t)));

    memcpy(&section->data, header, sizeof(IMAGE_SECTION_HEADER));
    slist_add(&pe->section_list, &section->node);
  }

  return true;
}

IMAGE_SECTION_HEADER* pe_section_first(int fd)
{
  if (fd == INVALID_PE){
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return slist_first_entry(&pe->section_list, section_t, data, node);
}

IMAGE_SECTION_HEADER* pe_section_next(IMAGE_SECTION_HEADER* it)
{
  if (it == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(it, section_t, data, node);
}

/***********************************************************************
 *
 *  pe export
 *
 **********************************************************************/

bool parse_export(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_EXPORT)->Size;

  //无导出函数
  if (block_rva == 0 || block_size == 0){
    return true;
  }

  raw_t block_raw = rva_to_raw(fd, block_rva);
  if (block_raw == INVALID_RAW) {
    errno = EINVAL;
    return false;
  }

  IMAGE_EXPORT_DIRECTORY* export_header
    = (IMAGE_EXPORT_DIRECTORY*)(pe->stream + block_raw);

  raw_t raw_name = rva_to_raw(fd, export_header->Name);
  if (raw_name == INVALID_RAW) {
    errno = EINVAL;
    return false;
  }

  pe->dll_name =  (const char*)(pe->stream + raw_name);

  if (export_header->NumberOfFunctions > 1024){
    errno = EINVAL;
    return false;
  }

  //获取导出函数名称序号数组
  raw_t raw_name_ordinals = rva_to_raw(fd, export_header->AddressOfNameOrdinals);
  if (raw_name_ordinals == INVALID_RAW) {
    errno = EINVAL;
    return false;
  }

  //获取导出函数名称数组
  raw_t raw_names = rva_to_raw(fd, export_header->AddressOfNames);
  if (raw_names == INVALID_RAW) {
    errno = EINVAL;
    return false;
  }

  //获取导出函数地址数组
  raw_t raw_functions = rva_to_raw(fd, export_header->AddressOfFunctions);
  if (raw_functions == INVALID_RAW) {
    errno = EINVAL;
    return false;
  }

  //先初始化序号和地址
  for (size_t i=0; i < export_header->NumberOfFunctions; i++) {
    export_api_t* api = (export_api_t*)malloc(sizeof(export_api_t));
    if (api == NULL) {
      return false;
    }
    memset(api, 0, sizeof(export_api_t));

    api->data.FunctionVirtualAddress = ((rva_t*)(pe->stream + raw_functions))[i];
    api->data.Ordinal = export_header->Base + (int32_t)i;
    //api name
    for(size_t j = 0; i < export_header->NumberOfNames; j++) {
      int oridinal = (int)(((uint16_t*)(pe->stream + raw_name_ordinals))[j]);
      if (oridinal != (int)i)
        continue;

      rva_t rva = ((rva_t*)(pe->stream + raw_names))[j];
      //可以按照名称进行导出
      raw_t raw = rva_to_raw(fd, rva);
      if (raw == INVALID_RAW)
        continue;

      strncpy(api->data.FunctionName, pe->stream + raw, 
        sizeof(api->data.FunctionName) - 1);
      break;
    }

    slist_add(&pe->export_apis, &api->node);
  }

  return true;
}

IMAGE_EXPORT_FUNCTION *pe_export_first(int fd)
{
  if (fd == INVALID_PE){
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return slist_first_entry(&pe->export_apis, export_api_t, data, node);
}

IMAGE_EXPORT_FUNCTION *pe_export_next(IMAGE_EXPORT_FUNCTION* iter)
{
  if (iter == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(iter, export_api_t, data, node);
}

const char* pe_export_dllname(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return pe->dll_name;
}

/***********************************************************************
 *
 *  pe import
 *
 **********************************************************************/

bool parse_import(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_IMPORT)->Size;

  if (block_rva == 0 || block_size == 0) {
    //表示没有导入表， 这种情况极少， 但还是存在
    //c:\\windows\\system32\\lz32.dll就是
    errno = ENOENT;
    return false;
  }

  raw_t raw = rva_to_raw(fd, block_rva);
  if (raw == INVALID_RAW) {
    errno = ERANGE;
    return false;
  }

  //计算IMAGE_IMPORT_DESCRIPTOR的个数
  IMAGE_IMPORT_DESCRIPTOR* pDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(pe->stream + raw);
  int num_module = 0;
  do {
    //最后一个全零的DESCRIPTOR表示结束
    IMAGE_IMPORT_DESCRIPTOR zero;
    memset(&zero, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (0 == memcmp(&pDescriptor[num_module],
                    &zero,
                    sizeof(IMAGE_IMPORT_DESCRIPTOR)))
      break;

    IMAGE_IMPORT_DESCRIPTOR *import_descriptor
      = (IMAGE_IMPORT_DESCRIPTOR*)(pe->stream
         + raw
         + num_module * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    import_dll_t* dll = (import_dll_t*)malloc(sizeof(import_dll_t));
    if (dll == NULL) {
      return false;
    }
    memset(dll, 0, sizeof(import_dll_t));
    memcpy(&dll->data, import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    slist_add(&pe->import_dlls, &dll->node);

    //枚举该模块的导入函数列表
    raw_t raw_thunk = 0;
    rva_t rva_iat = 0;
    if (import_descriptor->OriginalFirstThunk == 0) {
      //OriginalFirstThunk为0， 只能去读FirstThunk的值了
      raw_thunk = rva_to_raw(fd, import_descriptor->FirstThunk);
      rva_iat = import_descriptor->FirstThunk;
    } else {
      raw_thunk = rva_to_raw(fd, import_descriptor->OriginalFirstThunk);
      rva_iat = import_descriptor->FirstThunk;
    }

    if (raw_thunk >= pe->size) {
      errno = ERANGE;
      return false;
    }

    IMAGE_THUNK_DATA32* thunks = (IMAGE_THUNK_DATA32*)(pe->stream + raw_thunk);
    uint32_t num_api = 0;
    do {
      //最后一个全零的IMAGE_THUNK_DATA表示结束
      IMAGE_THUNK_DATA32 zero;
      memset(&zero, 0, sizeof(IMAGE_THUNK_DATA32));
      if (0 == memcmp(&thunks[num_api], &zero, sizeof(IMAGE_THUNK_DATA32)))
        break;

      import_api_t* api = (import_api_t*)malloc(sizeof(import_api_t));
      if (api == NULL) {
        return false;
      }
      memset(api, 0, sizeof(import_api_t));

      api->data.ThunkOffset = (uint32_t)((char*)&thunks[num_api] - pe->stream);
      api->data.ThunkRVA
        = raw_to_rva(fd, raw_thunk + num_api*sizeof(IMAGE_THUNK_DATA32));
      api->data.ThunkValue = thunks[num_api].u1.Function;
      if (thunks[num_api].u1.Ordinal & IMAGE_ORDINAL_FLAG32)  {
        //最高位为1, 表示序号方式导入函数, 函数名称
        api->data.OffsetName = 0;
        api->data.FunctionOrdinal
          = (uint16_t)(thunks[num_api].u1.Ordinal & 0x0000FFFF);
      } else  {
        //字符串类型导入函数
        raw_t raw_name = rva_to_raw(fd, thunks[num_api].u1.AddressOfData);
        if (raw_name == INVALID_RAW) {
          free(api);
          api = NULL;
          errno = ERANGE;
          continue;
        }

        api->data.OffsetName = raw_name + sizeof(uint16_t);
        IMAGE_IMPORT_BY_NAME *import_name
          = (IMAGE_IMPORT_BY_NAME*)(pe->stream + raw_name);
        strncpy(api->data.FunctionName,
                (char*)import_name->Name,
                sizeof(api->data.FunctionName) - 1);
        api->data.FunctionHint = (uint16_t)(import_name->Hint);
      }

      api->data.iat = rva_iat + num_api * sizeof(rva_t);
      slist_add(&dll->api_list, &api->node);
    } while(++num_api);
  }while(++num_module);

  return true;
}

bool pe_import_dllname(
    int fd, 
    IMAGE_IMPORT_DESCRIPTOR* import_dll,
    char* dllname, 
    int name_len)
{
  if (fd == INVALID_PE || import_dll == NULL) {
    errno = EINVAL;
    return false;
  }

  //获取导入模块名称
  raw_t raw_name = rva_to_raw(fd, import_dll->Name);
  if (raw_name == INVALID_RAW )  {
    errno = ERANGE;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  strncpy(dllname, pe->stream + raw_name, name_len - 1);
  return true; 
}



IMAGE_IMPORT_DESCRIPTOR* pe_import_dll_first(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return slist_first_entry(&pe->import_dlls, import_dll_t, data, node);
}

IMAGE_IMPORT_DESCRIPTOR* pe_import_dll_next(IMAGE_IMPORT_DESCRIPTOR* iter)
{
  if (iter == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(iter, import_dll_t, data, node);
}

int pe_import_dll_count(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return -1;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  int count = 0;
  IMAGE_IMPORT_DESCRIPTOR* dll = pe_import_dll_first(fd);
  for(; dll != NULL; dll = pe_import_dll_next(dll)) {
    count++;
  }
  
  return count;
}

IMAGE_IMPORT_FUNCTION* pe_import_api_first(IMAGE_IMPORT_DESCRIPTOR* import_dll)
{
  if (import_dll == NULL) {
    errno = EINVAL;
    return NULL;
  }

  import_dll_t* dll = container_of(import_dll, import_dll_t, data);
  if (dll->api_list.first == NULL) {
    return NULL;
  }

  return slist_first_entry(&dll->api_list, import_api_t, data, node);
}

IMAGE_IMPORT_FUNCTION* pe_import_api_next(IMAGE_IMPORT_FUNCTION* iter)
{
  if (iter == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(iter, import_api_t, data, node);
}

int pe_import_api_count(IMAGE_IMPORT_DESCRIPTOR* dll)
{
  if (dll == NULL) {
    errno = EINVAL;
    return NULL;
  }

  int count = 0;
  IMAGE_IMPORT_FUNCTION* api = pe_import_api_first(dll);
  for(; api != NULL; api = pe_import_api_next(api)) {
    count ++;
  }

  return count;
}

/**********************************************************************
 *
 * pe bound
 *
 **********************************************************************/

char* pe_restype_name(int res_type)
{
  switch(res_type)
  {
  case 1:
    return (char*)"CURSOR";
    break;
  case 2:
    return (char*)"BITMAP";
    break;
  case 3:
    return (char*)"ICON";
    break;
  case 4:
    return (char*)"MENU";
    break;
  case 5:
    return (char*)"DIALOG";
    break;
  case 6:
    return (char*)"STRING";
    break;
  case 7:
    return (char*)"FONTDIR";
    break;
  case 8:
    return (char*)"FONT";
    break;
  case 9:
    return (char*)"ACCELERATOR";
    break;
  case 10:
    return (char*)"RCDATA";
    break;
  case 11:
    return (char*)"MESSAGETABLE";
    break;
  case 12:
    return (char*)"GROUP_CURSOR";
    break;
  case 14:
    return (char*)"GROUP_ICON";
    break;
  case 16:
    return (char*)"VERSION";
    break;
  case 17:
    return (char*)"DLGINCLUDE";
    break;
  case 19:
    return (char*)"PLUGPLAY";
    break;
  case 20:
    return (char*)"VXD";
    break;
  case 21:
    return (char*)"ANICURSOR";
    break;
  case 22:
    return (char*)"ANIICON";
    break;
  case 23:
    return (char*)"RT_HTML";
    break;
  case 24:
    return (char*)"MANIFEST";
    break;
  case 0xF0:
    return (char*)"DIALOG_DATA";
    break;
  case 0xF1:
    return (char*)"TOOLBAR";
    break;
  default:
    return (char*)"UNKNOWN";
    break;
  }
}

bool pe_resource_name(int fd,  IMAGE_RESOURCE_DIRECTORY_ENTRY* res,
    char* name, int max_len)
{
  if (fd == INVALID_PE || res == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;

  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->Size;

  if (block_rva == 0 || block_size == 0) {
    errno = ENOENT;
    return NULL;
  }

  raw_t raw = rva_to_raw(fd, block_rva);
  if (raw == INVALID_RAW) {
    errno = ERANGE;
    return NULL;
  }

  if (res->NameOffset + raw >= pe->size) {
    errno = ERANGE;
    return NULL;
  }

  IMAGE_RESOURCE_DIR_STRING_U* pString =
    (IMAGE_RESOURCE_DIR_STRING_U*)(pe->stream + raw + res->NameOffset);
  int cch = 0;
  if (pString->Length <= (max_len<<1)) {
    cch = pString->Length >> 1;
  } else {
    cch = max_len;
  }
  ucs2tombs(name, (ucs2_t*)pString->NameString, cch);
  return true; 
}

IMAGE_RESOURCE_DATA_ENTRY* pe_resource_data(
    int fd, 
    IMAGE_RESOURCE_DIRECTORY_ENTRY* entry)
{
  if (fd == INVALID_PE || entry == NULL) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;

  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->Size;

  if (block_rva == 0 || block_size == 0) {
    errno = ENOENT;
    return NULL;
  }

  raw_t raw = rva_to_raw(fd, block_rva);
  if (raw == INVALID_RAW) {
    errno = ERANGE;
    return NULL;
  }

  if (entry->OffsetToData + raw >= pe->size) {
    errno = ERANGE;
    return NULL;
  }

  return (IMAGE_RESOURCE_DATA_ENTRY*)(pe->stream + raw + entry->OffsetToData); 
}

bool parse_resource_dir(
    pe_t* pe, 
    raw_t raw_root,
    IMAGE_RESOURCE_DIRECTORY* ResDir, 
    slist_t* res_list)
{
  int cRes = ResDir->NumberOfNamedEntries + ResDir->NumberOfIdEntries;
  if (cRes > 512) {
    return true;
  }
  IMAGE_RESOURCE_DIRECTORY_ENTRY* Entry
    = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(ResDir + 1);

  //枚举子资源
  for (int i = 0; i < cRes; i++) {
    if (Entry[i].DataIsDirectory) {
      //资源目录
      //递归
      if (Entry[i].OffsetToDirectory != 0) {
        raw_t raw_dir = raw_root + Entry[i].OffsetToDirectory;
        if (raw_dir >= pe->size) {
          //放弃该资源项
        } else {
          IMAGE_RESOURCE_DIRECTORY* subdir =
            (IMAGE_RESOURCE_DIRECTORY*)(pe->stream + raw_dir);
          resource_t* res = (resource_t*)malloc(sizeof(resource_t));
          if (res == NULL) {
            return false;
          }
          memset(res, 0, sizeof(resource_t));
          memcpy(&res->data, &Entry[i], sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
          slist_add(res_list, &res->node);
          parse_resource_dir(pe, raw_root, subdir, &res->child);
        }
      }
    } else {
      //资源数据
      if (Entry[i].OffsetToData + raw_root < pe->size) {
        resource_t* res = (resource_t*)malloc(sizeof(resource_t));
        if (res == NULL) {
          return false;
        }
        memset(res, 0, sizeof(resource_t));
        memcpy(&res->data, &Entry[i], sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        slist_add(res_list, &res->node);
      }
    }
  }

  return true;
}

bool parse_resource(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;

  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->Size;

  if (block_rva == 0 || block_size ==0) {
    return true;
  }

  raw_t raw = rva_to_raw(fd, block_rva);
  if (raw == INVALID_RAW) {
    errno = ERANGE;
    return false;
  }

  IMAGE_RESOURCE_DIRECTORY* pRootDirectory
    = (IMAGE_RESOURCE_DIRECTORY*)(pe->stream + raw);
  return parse_resource_dir(pe, raw, pRootDirectory, &pe->resource);
}

IMAGE_RESOURCE_DIRECTORY_ENTRY* pe_resource_first(
    int fd,
    IMAGE_RESOURCE_DIRECTORY_ENTRY* parent)
{
  if (fd == INVALID_PE ) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;

  slist_t* list = NULL;
  if (parent == NULL) {
    list = &pe->resource;
  } else {
    resource_t *node = container_of(parent, resource_t, data);
    list = &node->child;
  }

  return slist_first_entry(list, resource_t, data, node);
}

IMAGE_RESOURCE_DIRECTORY_ENTRY* pe_resource_next(
  IMAGE_RESOURCE_DIRECTORY_ENTRY* prev)
{
  if (prev == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(prev, resource_t, data, node);
}


/**********************************************************************
 *
 * pe relocation
 *
 **********************************************************************/

bool parse_reloc(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_BASERELOC)->Size;

  if (block_rva == 0 || block_size == 0)
    return true;

  raw_t raw = rva_to_raw(fd, block_rva);
  if (raw == INVALID_RAW) {
    errno = ERANGE;
    return false;
  }

  IMAGE_BASE_RELOCATION *base_relocation
    = (IMAGE_BASE_RELOCATION*)(pe->stream + raw);

  //获取重定位项的总数
  while(((const char*)base_relocation < (pe->stream + raw + block_size))
    && (base_relocation->SizeOfBlock != 0)) {
    //rva_t block_rva = base_relocation->VirtualAddress;
    int block_cItem = (base_relocation->SizeOfBlock
                 - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

    uint16_t* items = (uint16_t*)(base_relocation + 1);
    for (int i=0; i < block_cItem ; i++) {
      reloc_t* reloc = (reloc_t*)malloc(sizeof(reloc_t));
      if (reloc == NULL) {
        return false;
      }
      memset(reloc, 0, sizeof(reloc_t));

      reloc->data.rva = (items[i] & 0x0FFF) + base_relocation->VirtualAddress;
      reloc->data.type = ((items[i] & 0x0F000) >> 12);

      if (reloc->data.type == IMAGE_REL_BASED_ABSOLUTE) {
        //对齐用， 没实际作用
        reloc->data.rva = 0;
      }

      slist_add(&pe->reloc_list, &reloc->node);
    }

    //下一个Relocation Block
    base_relocation
      = (IMAGE_BASE_RELOCATION*)((char*)base_relocation
                               + base_relocation->SizeOfBlock);
  }

  return true;
}

IMAGE_RELOCATION_ITEM* pe_reloc_first(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return slist_first_entry(&pe->reloc_list, reloc_t, data, node);
}

IMAGE_RELOCATION_ITEM* pe_reloc_next(IMAGE_RELOCATION_ITEM* iter)
{
  if (iter == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(iter, reloc_t, data, node);
}

/**********************************************************************
 *
 * pe bound
 *
 **********************************************************************/

bool parse_bound(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)->VirtualAddress;
  rva_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)->Size;

  if (block_rva == 0 || block_size == 0) {
    return true;
  }

  if (block_rva >= pe->size) {
    //SetLastError(ERROR_BAD_EXE_FORMAT);
    return false;
  }

  IMAGE_BOUND_IMPORT_DESCRIPTOR *descriptor
    = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(pe->stream + block_rva);
  descriptor = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(pe->stream  + block_rva);

  while(descriptor->OffsetModuleName != 0) {
    bound_t* bound_dll = (bound_t*)malloc(sizeof(bound_t));
    if (bound_dll == NULL) {
      return false;
    }
    memset(bound_dll, 0, sizeof(bound_t));
    memcpy(&bound_dll->data, descriptor, sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
    slist_add(&pe->bound_list, &bound_dll->node);

    descriptor = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)((char*)descriptor
                          + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR)
                          + descriptor->NumberOfModuleForwarderRefs
                          * sizeof(IMAGE_BOUND_FORWARDER_REF));
  }

  return true;
}

const char* pe_bound_import_dllname(int fd, IMAGE_BOUND_IMPORT_DESCRIPTOR* dll)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  rva_t block_rva
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)->VirtualAddress;
  rva_t block_size
    = DIRECTORY_ENTRY(pe->stream, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)->Size;

  if (block_rva == 0 || block_size == 0) {
    errno = ENOENT;
    return NULL;
  }

  if (block_rva >= pe->size) {
    errno = ERANGE;
    return NULL;
  }

  if (block_rva + dll->OffsetModuleName >= pe->size) {
    errno = ERANGE;
    return NULL;
  } 
  return pe->stream + block_rva + dll->OffsetModuleName;
}


IMAGE_BOUND_IMPORT_DESCRIPTOR* pe_bound_import_first(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return slist_first_entry(&pe->bound_list, bound_t, data, node);
}

IMAGE_BOUND_IMPORT_DESCRIPTOR* pe_bound_import_next(
    IMAGE_BOUND_IMPORT_DESCRIPTOR* iter)
{
  if (iter == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(iter, bound_t, data, node);
}

/**********************************************************************
 *
 * pe section
 *
 **********************************************************************/
//由于脱壳的需要， 有的时候是不知道文件数据大小的
bool copy_section_header(int fd,int sect_id, IMAGE_SECTION_HEADER *sect_header)
{
  if (fd == INVALID_PE || sect_header == NULL) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  if (sect_id >= pe->nt->FileHeader.NumberOfSections) {
    errno = EINVAL;
    return false;
  }

  memcpy(sect_header, GET_SECTION_HEADER(pe->nt, sect_id), 
    sizeof(IMAGE_SECTION_HEADER));
  return true;
}

IMAGE_SECTION_HEADER* pe_section_header(int fd, int sect_id)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  if (sect_id < 0 || sect_id > pe->nt->FileHeader.NumberOfSections) {
    errno = EINVAL;
    return NULL;
  }

  return GET_SECTION_HEADER(pe->nt, sect_id);
}

//计算虚拟地址所在的节
int pe_section_by_rva(int fd, rva_t rva)
{
  if (fd == INVALID_PE || rva == INVALID_RVA) {
    errno = EINVAL;
    return INVALID_SECTION_ID;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  //枚举所有Section
  //uint32_t section_align_mask = pe->nt->OptionalHeader.SectionAlignment - 1;
  //uint32_t file_align = pe->nt->OptionalHeader.FileAlignment;
  //uint32_t file_align_mask = file_align - 1;

  int i=0;
  for(; i < pe->nt->FileHeader.NumberOfSections; i++)  {
    //判断RVA是否在该Section地址范围内
    IMAGE_SECTION_HEADER section;
    memset(&section, 0, sizeof(IMAGE_SECTION_HEADER));
    copy_section_header(fd, i, &section);
    if ((rva >= section.VirtualAddress)
     && (rva <= (section.VirtualAddress + section.Misc.VirtualSize - 1)))
      break;
  }

  if (i >= pe->nt->FileHeader.NumberOfSections)
    return -1;
  else
    return i;
}

//计算文件偏移所在的节
int  pe_section_by_raw(int fd, raw_t raw)
{
  if (fd == INVALID_PE)
    return INVALID_SECTION_ID;

  rva_t rva = raw_to_rva(fd, raw);
  if (rva == INVALID_RVA)
    return INVALID_SECTION_ID;

  return pe_section_by_rva(fd, rva);
}



/**********************************************************************
 *
 * pe overlay
 *
 **********************************************************************/

bool parse_overlay(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  //将所有的节的长度进行累加
  uint32_t image_size = 0;
  for(int i = 0; i < pe->nt->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER section;
    memset(&section, 0, sizeof(IMAGE_SECTION_HEADER));
    copy_section_header(fd, i, &section);
    image_size += ALIGN(section.SizeOfRawData,
                        pe->nt->OptionalHeader.FileAlignment);
  }
  image_size += pe->nt->OptionalHeader.SizeOfHeaders;

  if (image_size > pe->size) {  //损坏的PE
    pe->overlay.offset_in_file = 0;
    pe->overlay.size = 0;
    return true;
  }

  if (image_size == pe->size) { //没有附加数据
    pe->overlay.offset_in_file = 0;
    pe->overlay.size = 0;
  } else {
    pe->overlay.offset_in_file = image_size;
    pe->overlay.size = (uint32_t)pe->size - image_size;
  }
  return true;
}

IMAGE_OVERLAY* pe_overlay(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }
  pe_t* pe = (pe_t*)(intptr_t)fd;
  return &pe->overlay;
}


/**********************************************************************
 *
 * pe icon
 *
 **********************************************************************/

bool pe_icon_file(int fd, const char* ico_file)
{
  if (fd == INVALID_PE || ico_file == NULL) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  bool is_success = false;

  //遍历资源, 找到ICON GROUPS资源 
  IMAGE_RESOURCE_DIRECTORY_ENTRY *res = NULL;
  IMAGE_RESOURCE_DATA_ENTRY* icon_group = NULL;
  slist_for_each_entry(res, &pe->resource, resource_t, data, node) {
    if (res->Id == 14 && IS_RESOURCE_DIRECTORY(res)) {
      resource_t* node = container_of(res, resource_t, data);
      slist_t* res_list = &node->child;
      IMAGE_RESOURCE_DIRECTORY_ENTRY* res_2 = NULL;
      slist_for_each_entry(res_2, res_list, resource_t, data, node) {
        if (IS_RESOURCE_DIRECTORY(res_2)) {
          resource_t* node = container_of(res_2, resource_t, data);
          slist_t* res_3_list = &node->child;
          IMAGE_RESOURCE_DIRECTORY_ENTRY* res_3 = NULL;
          slist_for_each_entry(res_3, res_3_list, resource_t, data, node) {
            if (!IS_RESOURCE_DIRECTORY(res_3)) {
              icon_group = pe_resource_data(fd, res_3);
              if (icon_group != NULL){
                break;
              }
            }
          }
        }

        if (icon_group != NULL) {
          break;
        }
      }
    }

    if (icon_group != NULL) {
      break;
    }
  }

  if (icon_group == NULL || icon_group->OffsetToData == 0 || icon_group->Size == 0 ) {
    errno = ENOENT;
    return false;
  }

  raw_t raw = rva_to_raw(fd, icon_group->OffsetToData);
  if (raw == INVALID_RAW) {
    //printf("invalid icon group raw");
    return false;
  }

  GRPICONDIR* icon_dir = (GRPICONDIR*)(pe->stream + raw);
  if (icon_group->Size != sizeof(GRPICONDIR)
                         + (icon_dir->idCount-1)*sizeof(GRPICON_DIR_ENTRY)) {
    //printf("invalid icon group size");
    return false;
  }

  //获取资源的位置和长度
  IMAGE_RESOURCE_DIRECTORY_ENTRY* res_icon = NULL;
  slist_for_each_entry(res_icon, &pe->resource, resource_t, data, node) {
    if (res_icon->Id == 3) {
      break;
    }
  }

  if (res_icon == NULL) {
    errno = ENOENT;
    return false;
  }


  FILE* fp = fopen(ico_file, "wb");
  if (fp==NULL) {
    //printf("open file fail");
    return false;
  }


  size_t ico_header_size = sizeof(ICON_DIR)
                           + (icon_dir->idCount-1)*sizeof(ICON_ENTRY);
  ICON_DIR* ico_header = (ICON_DIR*)malloc(ico_header_size);
  if (ico_header == NULL) {
    is_success = false;
    fclose(fp);
    fp = NULL;
    return false;
  }

  fseek(fp, (long)ico_header_size, SEEK_SET);
  for (int i=0; i<icon_dir->idCount; i++) {
    ico_header->idEntries[i].bWidth = icon_dir->idEntries[i].bWidth;
    ico_header->idEntries[i].bHeigh = icon_dir->idEntries[i].bHeigh;
    ico_header->idEntries[i].bColorCount = icon_dir->idEntries[i].bColorCount;
    ico_header->idEntries[i].bReserved = icon_dir->idEntries[i].bReserved;
    ico_header->idEntries[i].wPlanes = icon_dir->idEntries[i].wPlanes;
    ico_header->idEntries[i].wBitCount = icon_dir->idEntries[i].wBitCount;

    resource_t* res = container_of(res_icon, resource_t, data);
    IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = NULL;
    slist_for_each_entry(entry, &res->child, resource_t, data, node) {
      if (entry->Id == icon_dir->idEntries[i].nID 
        && IS_RESOURCE_DIRECTORY(entry)) {
        break;
      }
    }

    if(entry == NULL) {
      //在ICON资源目录下没有找到目标图标资源
      continue;
    }

    resource_t* node = container_of(entry, resource_t, data);
    entry = NULL;
    slist_for_each_entry(entry, &node->child, resource_t, data, node) {
      if (!IS_RESOURCE_DIRECTORY(entry)) {
        break;
      }
    }

    if (entry == NULL) {
      continue;
    }

    IMAGE_RESOURCE_DATA_ENTRY* icon = pe_resource_data(fd, entry);
    if (icon->Size != 0) {
      raw_t icon_raw = rva_to_raw(fd, icon->OffsetToData);
      if (icon_raw != INVALID_RAW) {
        //write ico data
        if (icon->Size != fwrite(pe->stream + icon_raw, 1, icon->Size, fp)){
          //printf("write ico data failed");
          is_success = false;
          goto ret_door;
        }
        ico_header->idEntries[i].dwBytesInRes = icon->Size;
        ico_header->idEntries[i].dwImageOffset = ftell(fp) - icon->Size;
      } else {
        //ico data overrun
        //printf("ico data overrun");
        ico_header->idEntries[i].dwBytesInRes = 0;
        ico_header->idEntries[i].dwImageOffset = 0;
      }
    } else {
      //ico data not found
      //printf("ico data not found");
      ico_header->idEntries[i].dwBytesInRes = 0;
      ico_header->idEntries[i].dwImageOffset = 0;
    }
  }

  //write ico file header
  ico_header->idCount = icon_dir->idCount;
  ico_header->idType = icon_dir->idType;
  ico_header->idReserved = icon_dir->idReserved;
  fseek(fp, 0, SEEK_SET);
  if (ico_header_size != fwrite(ico_header, 1, ico_header_size, fp)){
    //printf("write ico header failed");
    is_success = false;
    goto ret_door;
  }

  //success
  is_success = true;

ret_door:
  fclose(fp);
  if (ico_header != NULL) {
    free(ico_header);
    ico_header = NULL;
  }

  return is_success;
}


/**********************************************************************
 *
 * pe version
 *
 **********************************************************************/

 #pragma pack(push)
 #pragma pack(1)
typedef struct _VS_VERSIONINFO
{
    uint16_t  wLength;
    uint16_t  wValueLength;
    uint16_t  wType;
    uint16_t   szKey[1];
    uint16_t  Padding1[1];
    VS_FIXEDFILEINFO Value;
    uint16_t  Padding2[1];
    uint16_t  Children[1];
}VS_VERSIONINFO;

typedef struct _String
{
    uint16_t   wLength;
    uint16_t   wValueLength;
    uint16_t   wType;
    uint16_t    szKey[1];
    uint16_t   Padding[1];
    uint16_t   Value[1];
}String;

typedef struct _StringTable
{
    uint16_t   wLength;
    uint16_t   wValueLength;
    uint16_t   wType;
    uint16_t    szKey[1];
    uint16_t   Padding[1];
    String     Children[1];
}StringTable;

typedef struct _StringFileInfo
{
    uint16_t   wLength;
    uint16_t   wValueLength;
    uint16_t   wType;
    uint16_t    szKey[1];
    uint16_t   Padding[1];
    StringTable Children[1];
}StringFileInfo;

typedef struct _Var
{
    uint16_t  wLength;
    uint16_t  wValueLength;
    uint16_t  wType;
    uint16_t  szKey[1];
    uint16_t  Padding[1];
    uint32_t  Value[1];
}Var;

typedef struct _VarFileInfo
{
    uint16_t  wLength;
    uint16_t  wValueLength;
    uint16_t  wType;
    uint16_t   szKey[1];
    uint16_t  Padding[1];
    Var   Children[1];
}VarFileInfo; 
#pragma pack(pop) 

bool parse_fixed_version(pe_t* pe, VS_FIXEDFILEINFO* pValue)
{
    if(VS_FFI_SIGNATURE != pValue->dwSignature ) {
      return false;
    }

    if(VS_FFI_STRUCVERSION != pValue->dwStrucVersion ) {
      return false;
    }
    
    // 输出 VS_FIXEDFILEINFO 结构体信息
    version_t* version = (version_t*)malloc(sizeof(version_t));
    if( version == NULL) {
      return false;
    }
    memset(version, 0, sizeof(version_t));
    _wcstombs(version->data.name, L"Signature", MAX_VER_NAME_LEN - 1);
    _snprintf(version->data.value, MAX_VER_VALUE_LEN - 1, "%d.%d", 
      pValue->dwStrucVersion >> 16,
      pValue->dwStrucVersion & 0xFFFF);
    slist_add(&pe->version, &version->node);

    version = (version_t*)malloc(sizeof(version_t));
    if (version == NULL) {
      return false;
    }
    memset(version, 0, sizeof(version_t));
    _wcstombs(version->data.name, L"FileVersion", MAX_VER_NAME_LEN - 1);
    _snprintf(version->data.value, MAX_VER_VALUE_LEN - 1,  "%d.%d.%d.%d",
        pValue->dwFileVersionMS >> 16,
        pValue->dwFileVersionMS & 0xFFFF,
        pValue->dwFileVersionLS >> 16,
        pValue->dwFileVersionLS & 0xFFFF);
    slist_add(&pe->version, &version->node);

    version = (version_t*)malloc(sizeof(version_t));
    if (version == NULL) {
      return false;
    }
    memset(version, 0, sizeof(version_t));
    _wcstombs(version->data.name, L"ProductVersion", MAX_VER_NAME_LEN - 1);
    _snprintf(version->data.value, MAX_VER_VALUE_LEN - 1, "%d.%d.%d.%d",
        pValue->dwProductVersionMS >> 16,
        pValue->dwProductVersionMS & 0xFFFF,
        pValue->dwProductVersionLS >> 16,
        pValue->dwProductVersionLS & 0xFFFF);
    slist_add(&pe->version, &version->node);

    version = (version_t*)malloc(sizeof(version_t));
    if (version == NULL) {
      return false;
    }
    memset(version, 0, sizeof(version_t));
    _wcstombs(version->data.name, L"FileFlagsMask", MAX_VER_NAME_LEN -1);
    _snprintf(version->data.value, MAX_VER_VALUE_LEN - 1, "%s%x", 
        pValue->dwFileFlagsMask ? "0x" : "",
        pValue->dwFileFlagsMask);
    slist_add(&pe->version, &version->node);

    version = (version_t*)malloc(sizeof(version_t));
    if (version == NULL) {
      return false;
    }
    memset(version, 0, sizeof(version_t));
    _wcstombs(version->data.name, L"FileDate", MAX_VER_NAME_LEN - 1);
    _snprintf(version->data.value, MAX_VER_VALUE_LEN - 1, "%x.%x", 
        pValue->dwFileDateMS, 
        pValue->dwFileDateLS);
    slist_add(&pe->version, &version->node);
    return true;
}

#define ROUND_OFFSET(a,b,r)    (((uint8_t*)(b) - (uint8_t*)(a) + ((r) - 1)) & ~((r) - 1))
#define ROUND_POS(b, a, r)    (((uint8_t*)(a)) + ROUND_OFFSET(a, b, r))

// 获取版本号信息入口点
IMAGE_RESOURCE_DATA_ENTRY* 
get_version_block(PIMAGE_RESOURCE_DIRECTORY pRootRec)
{
    uint16_t nCount = pRootRec->NumberOfIdEntries 
      + pRootRec->NumberOfNamedEntries;
    if (nCount >= 512) {
      return NULL;
    }

    for ( uint16_t i = 0; i < nCount; ++i ) {
        IMAGE_RESOURCE_DIRECTORY_ENTRY* pFirstEntry 
          = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint8_t*)pRootRec +
            sizeof(IMAGE_RESOURCE_DIRECTORY)) + i;
        
        uint16_t id_ver = pFirstEntry->Id;
        if (  id_ver != 16 )
            continue;

        // 进入目录
        if ( pFirstEntry->DataIsDirectory == 0x01 ) {
            IMAGE_RESOURCE_DIRECTORY* pFirstDir = (IMAGE_RESOURCE_DIRECTORY*) ( (uint8_t*)pRootRec + pFirstEntry->OffsetToDirectory );
            uint16_t nDirCount = pFirstDir->NumberOfNamedEntries + pFirstDir->NumberOfIdEntries;

            // 第二层目录(资源代码页)
            for ( uint16_t nIndex = 0; nIndex < nDirCount; ++nIndex ) {
                IMAGE_RESOURCE_DIRECTORY_ENTRY* pSecondEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)( (uint8_t*)pFirstDir +
                    sizeof(IMAGE_RESOURCE_DIRECTORY) ) + nIndex;

                // 取第三层目录(资源数据入口)
                if ( pSecondEntry->DataIsDirectory == 1 )
                {
                    IMAGE_RESOURCE_DIRECTORY* pThirdDir = (IMAGE_RESOURCE_DIRECTORY*)( (uint8_t*)pRootRec + pSecondEntry->OffsetToDirectory );
                    if ( pThirdDir->NumberOfIdEntries + pThirdDir->NumberOfNamedEntries >= 1 )
                    {
                        // 有一个Entry
                        IMAGE_RESOURCE_DIRECTORY_ENTRY* pThirdEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)( (uint32_t*)pThirdDir +
                            sizeof(IMAGE_RESOURCE_DIRECTORY) / sizeof(uint32_t) );    
                        if ( pThirdEntry->DataIsDirectory == 0 )
                        {
                            IMAGE_RESOURCE_DATA_ENTRY* pData = (IMAGE_RESOURCE_DATA_ENTRY* )( (uint8_t*)pRootRec + pThirdEntry->OffsetToDirectory );
                            if ( pData )
                            {
                                // 找到真实数据入口点
                                return pData;
                            }
                        }
                    }
                }
            }
        }
    }

    return NULL;
}

bool parse_version(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  //setlocale(LC_ALL, "zh_CN.GBK");
  pe_t* pe = (pe_t*)(intptr_t)fd;

  // 获取资源目录
  IMAGE_DATA_DIRECTORY* pDataDir 
    = &pe->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if ( pDataDir->VirtualAddress == 0 || pDataDir->Size == 0 ) {
      return false;
  }

  // 读取资源在文件中的偏移位置
  raw_t dwOffset = rva_to_raw(fd, pDataDir->VirtualAddress);
  if ( INVALID_RAW == dwOffset )
      return false;

  // 找到版本号位置
  IMAGE_RESOURCE_DATA_ENTRY* pVersionEntry = 
    get_version_block((IMAGE_RESOURCE_DIRECTORY*)(pe->stream + dwOffset));
  if ( pVersionEntry == NULL ) {
      return false;
  }


  // 得到文件中的偏移地址
  dwOffset = rva_to_raw(fd, pVersionEntry->OffsetToData);
  if ( 0 == dwOffset )
      return false;

  
  const char* version = pe->stream + dwOffset;
  //size_t versize = pVersionEntry->Size;
  VS_VERSIONINFO* pVS = (VS_VERSIONINFO*)version;
  char szkey[32] = {0};
  ucs2tombs(szkey, (ucs2_t*)pVS->szKey, sizeof(szkey) - 1);
  if( 0 != strcmp(szkey, "VS_VERSION_INFO")) {
    return false;
  }

  //printf(" (type:%d)\n", pVS->wType);
  uint8_t* pVt = (uint8_t*)&pVS->szKey[strlen(szkey) + 1];
  VS_FIXEDFILEINFO* pValue = (VS_FIXEDFILEINFO*)ROUND_POS(pVt, pVS, 4);
  if ( pVS->wValueLength ) {
      parse_fixed_version(pe, pValue);
  }

  // 遍历 VS_VERSIONINFO 子节点元素
  StringFileInfo* pSFI = 
    (StringFileInfo*)ROUND_POS(((uint8_t*)pValue) + pVS->wValueLength, pValue, 4);
  for ( ; ((uint8_t*) pSFI) < (((uint8_t*)pVS) + pVS->wLength);
      pSFI = (StringFileInfo*)ROUND_POS((((uint8_t*) pSFI) + pSFI->wLength), pSFI, 4))
  {
    // StringFileInfo / VarFileInfo
    char sfi_key[32] = {0};
    ucs2tombs(sfi_key, (ucs2_t*)pSFI->szKey, sizeof(sfi_key) - 1);
    if ( 0 == strncmp(sfi_key, "StringFileInfo", strlen("StringFileInfo"))){
      // 当前子节点元素是 StringFileInfo
      //_ASSERT(1 == pSFI->wType);
      //_ASSERT(!pSFI->wValueLength);

          // 遍历字串信息 STRINGTABLE 元素
      StringTable* pST = (StringTable*)ROUND_POS(&pSFI->szKey[strlen(sfi_key) + 1], pSFI, 4);
      for ( ; ((uint8_t*) pST) < (((uint8_t*) pSFI) + pSFI->wLength);
          pST = (StringTable*)ROUND_POS((((uint8_t*) pST) + pST->wLength), pST, 4))
      {
        //printf(" LangID: %S\n", pST->szKey);
        //_ASSERT( !pST->wValueLength );

        // 遍历字符串元素的 STRINGTABLE
        String* pS = (String*)ROUND_POS(&pST->szKey[ucs2len(pST->szKey) + 1], pST, 4);
        for ( ; ((uint8_t*) pS) < (((uint8_t*) pST) + pST->wLength);
          pS = (String*)ROUND_POS((((uint8_t*) pS) + pS->wLength), pS, 4))
        {
          ucs2_t* psVal = (ucs2_t*)ROUND_POS(&pS->szKey[ucs2len(pS->szKey) + 1], pS, 4);
          // 打印 <sKey> : <sValue>
          //printf("  %-18S: %.*S\n", pS->szKey, pS->wValueLength, psVal);
          version_t* item = (version_t*)malloc(sizeof(version_t));
          if (item == NULL) {
            return false;
          }
          memset(item, 0, sizeof(version_t));

          //_snwprintf(verinfo.name, (sizeof(verinfo.name) / 2) -1 , L"%S", pS->szKey);
          //memcpy(item->name, pS->szKey, sizeof(item->name) - sizeof(wchar_t));
          ucs2tombs(item->data.name, (ucs2_t*)pS->szKey, MAX_VER_NAME_LEN - 1);
          //_snwprintf(verinfo.value, (sizeof(verinfo.value) / 2) - 1, L"%.*S", 
          //    pS->wValueLength, psVal);
          //memcpy(item->value, psVal, sizeof(item->value) - sizeof(wchar_t));
          ucs2tombs(item->data.value, psVal, MAX_VER_NAME_LEN - 1);
          slist_add(&pe->version, &item->node);
        }
      }
    } else {
      // 当前子节点元素是 VarFileInfos
      //_ASSERT( 1 == pSFI->wType );
      VarFileInfo* pVFI = (VarFileInfo*) pSFI;
      //_ASSERT( 0 == wcscmp(pVFI->szKey, L"VarFileInfo") );
      //_ASSERT( !pVFI->wValueLength );

      // var元素VarFileInfo遍历（应该只有一个，但以防万一...）
      Var* pV = (Var*)ROUND_POS(&pVFI->szKey[ucs2len(pVFI->szKey) + 1], pVFI, 4);
      for ( ; ((uint8_t*) pV) < (((uint8_t*) pVFI) + pVFI->wLength);
          pV = (Var*)ROUND_POS((((uint8_t*) pV) + pV->wLength), pV, 4)) {
        //printf(" %S: ", pV->szKey);
        
        // 对16位的语言ID值，弥补标准的“翻译”VarFileInfo的元素的数组的遍历。
        ucs2_t* pwV = (ucs2_t*) ROUND_POS(&pV->szKey[ucs2len(pV->szKey) + 1], pV, 4);
        for (ucs2_t* wpos = pwV ; ((uint8_t*) wpos) < (((uint8_t*) pwV) + pV->wValueLength); wpos += 2)
        {
            //printf("%04x%04x ", (int)*wpos++, (int)(*(wpos + 1)));
        }

        //printf("\n");
      }
    }
  }

  //_ASSERT((LPBYTE)pSFI == ROUND_POS((((LPBYTE) pVS) + pVS->wLength), pVS, 4));

  // 返回主版本号
  //return pValue->dwFileVersionMS;  
  return true;
}

IMAGE_VERSION* pe_version_first(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return slist_first_entry(&pe->version, version_t, data, node);
}

IMAGE_VERSION* pe_version_next(IMAGE_VERSION* iter)
{
  if (iter == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(iter, version_t, data, node);
}


/**********************************************************************
 *
 * pe gap
 *
 **********************************************************************/
bool parse_gap(pe_t* pe)
{
  if (pe == NULL || pe == (pe_t*)-1) {
    errno = INVALID_PE;
    return false;
  }

  IMAGE_DOS_HEADER *dos_header = GET_DOS_HEADER(pe->stream);
  IMAGE_NT_HEADERS32 *nt_header = GET_NT_HEADER(pe->stream);
  size_t dwActualHeaderSize = dos_header->e_lfanew
                + sizeof(int)
                + sizeof(IMAGE_FILE_HEADER)
                + nt_header->FileHeader.SizeOfOptionalHeader
                + nt_header->FileHeader.NumberOfSections
                * sizeof(IMAGE_SECTION_HEADER);

  if (dwActualHeaderSize != nt_header->OptionalHeader.SizeOfHeaders) {
    gap_t* gap = (gap_t*)malloc(sizeof(gap_t));
    if (gap == NULL) {
      return false;
    }
    memset(gap, 0, sizeof(gap_t));

    gap->data.offset = dwActualHeaderSize;
    gap->data.size = nt_header->OptionalHeader.SizeOfHeaders
                              - dwActualHeaderSize;
    slist_add(&pe->gap_list, &gap->node);
  }

  for (int i= 0;
     i < nt_header->FileHeader.NumberOfSections ;
     i++ ) {
    IMAGE_SECTION_HEADER Header = {0};
    copy_section_header((intptr_t)pe, i, &Header);

    if (Header.Misc.VirtualSize < Header.SizeOfRawData) {
      gap_t* gap = (gap_t*)malloc(sizeof(gap_t));
      if (gap == NULL) {
        return false;
      }
      memset(gap, 0, sizeof(gap_t));

      gap->data.offset = Header.PointerToRawData + Header.Misc.VirtualSize;
      gap->data.size = Header.SizeOfRawData - Header.Misc.VirtualSize;
      slist_add(&pe->gap_list, &gap->node);
    }
  }

  return true;
}


IMAGE_GAP* pe_gap_first(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return NULL;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  return slist_first_entry(&pe->gap_list, gap_t, data, node);
}

IMAGE_GAP* pe_gap_next(IMAGE_GAP* iter)
{
  if (iter == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return slist_next_entry(iter, gap_t, data, node);
}

/*
bool pe_remove_last_section(int fd)
{
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)(intptr_t)fd;
  IMAGE_SECTION_HEADER Header;
  memset(&Header, 0, sizeof(IMAGE_SECTION_HEADER));
  if (!copy_section_header(fd, pe->nt->FileHeader.NumberOfSections -1,
               &Header))
    return false;

  //删除节数据
  memset((char*)pe->stream + (uint32_t)Header.PointerToRawData, 0, Header.SizeOfRawData);

  //删除节描述符
  IMAGE_SECTION_HEADER* pSectionHeader =
    (IMAGE_SECTION_HEADER*)((char*)pe->nt
                 + sizeof(int)
                 + sizeof(IMAGE_FILE_HEADER)
                 + pe->nt->FileHeader.SizeOfOptionalHeader);
  memset(pSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));

  //修改节数量
  pe->nt->FileHeader.NumberOfSections --;

  //修改SizeOfImage字段
  pe->nt->OptionalHeader.SizeOfImage
    -= ALIGN(Header.Misc.VirtualSize, pe->nt->OptionalHeader.SectionAlignment);
  return true;
}


bool LoadPERelocRoutine(
    rva_t rvaOwnerBlock,
    IMAGE_RELOCATION_ITEM* pItem,
    void* lpParam )
{
  char* image = (char*)lpParam;
  IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32*)image;
  rva_t delta = (rva_t)image - (rva_t)nt->OptionalHeader.ImageBase;
  *(rva_t*)(image +pItem->rva) += delta;
  return true;
}

bool LoadPE_IATRoutine(
    PIMPORT_FUNCTION pImportFunction,
    PIMPORT_MODULE pImportModule,
    void* lpParam )
{
#ifdef __GNUC__
  return false;
#else
  char* image = (char*)lpParam;
  IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32*)image;

  HMODULE hModule = LoadLibrary(pImportModule->ModuleName);
  if (hModule == NULL) {
    printf("load module %s failed", pImportModule->ModuleName);
    return false;  //go on
  }

  rva_t addr = (rva_t)GetProcAddress(hModule, pImportFunction->FunctionName);
  if (addr == NULL) {
    printf("get address %s failed", pImportFunction->FunctionName);
    return false;
  }
  printf("%-60s0x%08X\n", pImportFunction->FunctionName, pImportFunction->iat);
  // *(rva_t*)(image + pImportFunction->ThunkRVA) = addr;
  return true;
#endif
}

bool pe_load(int fd, char* image, size_t image_size)
{
#ifdef __GNUC__
  return false;
#else
  if (fd == INVALID_PE) {
    errno = EINVAL;
    return false;
  }

  pe_t* pe = (pe_t*)fd;
  if (image_size < pe->nt.OptionalHeader.SizeOfImage){
    return false;
  }

  //load pe headers
  memcpy(image, pe->stream, pe->nt.OptionalHeader.SizeOfHeaders);

  IMAGE_NT_HEADERS32 *image_nt = GET_NT_HEADER(image);

  //load all sections
  for (int i=0; i < pe->nt.FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER *section = GET_SECTION_HEADER(pe->nt,i);
    memcpy(image + section->VirtualAddress,
             pe->stream+section->PointerToRawData,
             section->SizeOfRawData );
    IMAGE_SECTION_HEADER *image_section = GET_SECTION_HEADER(image_nt,i);
    image_section->SizeOfRawData = ALIGN(section->SizeOfRawData,
                                          pe->nt.OptionalHeader.SectionAlignment);
    image_section->PointerToRawData = section->VirtualAddress;
  }

  //reloc
  if (!parse_reloc(fd) {
    printf("reloc failed\n");
    return false;
  }

  //build iat
  if (!EnumImportModuleAndFunction(stream,
                                      stream_size,
                                      NULL,
                                      NULL,
                                      LoadPE_IATRoutine,
                                      image)) {
    printf("iat failed\n");
    return false;
  }

  //modify imagebase
  //image_nt->OptionalHeader.ImageBase = (uint32_t)image;

  //modify FileAlignment
  image_nt->OptionalHeader.FileAlignment = nt->OptionalHeader.SectionAlignment;

  return true;
#endif
}
*/
