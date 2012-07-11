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
#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <assert.h>
#include "strconv.h"
#include "imgfmt.h"
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

int IsValidPE(
    const char* stream,
    size_t stream_size)
{
  IMAGE_DOS_HEADER* dos_header = GET_DOS_HEADER(stream);
  IMAGE_NT_HEADERS* pPEHeader = GET_NT_HEADER(stream);

  //读取PE头部数据
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }

  if ((size_t)dos_header->e_lfanew >= (size_t)stream_size)  {
    return false;
  }

  if (pPEHeader->Signature != IMAGE_NT_SIGNATURE
   || pPEHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
   || pPEHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ) {
    return false;
  }

  return true;
}

raw_t RvaToRaw(
    const char *stream,
    size_t stream_size,
    rva_t rva)
{
  if (stream == NULL || rva == INVALID_VIRTUAL_ADDRESS) {
    errno = EINVAL;
    return INVALID_FILE_OFFSET;
  }

  //枚举所有Section
  IMAGE_NT_HEADERS *nt_header = GET_NT_HEADER(stream);
  IMAGE_SECTION_HEADER *section = NULL;

  unsigned int sectin_align_mask
    = nt_header->OptionalHeader.SectionAlignment - 1;
  unsigned int file_align = nt_header->OptionalHeader.FileAlignment;
  unsigned int file_align_mask = file_align - 1;

  //计算rva在哪个节中
  raw_t raw = 0;
  for (size_t i=0; i < nt_header->FileHeader.NumberOfSections; i++) {
    section = GET_SECTION_HEADER(nt_header, i);
    if (rva >= section->VirtualAddress
     && rva <= (section->VirtualAddress + section->Misc.VirtualSize - 1)){
      raw = rva - section->VirtualAddress
                + section->PointerToRawData;
      goto ret;
    }
  }
  raw = rva;

ret:
  if (raw >= stream_size) {
    errno = ERANGE;
    return INVALID_FILE_OFFSET;
  }
  return raw;
}

rva_t RawToRva(
    const char* stream,
    raw_t raw)
{
  if (stream == NULL) {
    errno = EINVAL;
    return INVALID_VIRTUAL_ADDRESS;
  }

  //枚举所有Section
  IMAGE_NT_HEADERS* nt_header = GET_NT_HEADER(stream);

  for (size_t i=0; i < nt_header->FileHeader.NumberOfSections; i++) {
    //判断FileOffset是否在该Section地址范围内
    IMAGE_SECTION_HEADER *section = GET_SECTION_HEADER(nt_header, i);
    assert( section != NULL );
    if (raw >= section->PointerToRawData
     && raw <= (section->PointerToRawData+section->SizeOfRawData-1)){
      //rva = File Offset + k.
      return raw + section->VirtualAddress
                 - section->PointerToRawData;
    }
  }

  return INVALID_VIRTUAL_ADDRESS;
}

bool GetExportDllName(
    const char *stream,
    size_t stream_size,
    char *dll_name,
    size_t bufsize)
{
  if (stream == NULL
   /*|| IsBadReadPtr(stream, stream_size)*/
   || dll_name == NULL
   || bufsize == 0) {
    errno = EINVAL;
    return false;
  }

  memset(dll_name, 0, bufsize);
  rva_t block_rva
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_EXPORT)->Size;

  //无导出相关信息
  if (block_rva == 0 ){
    errno = ENOENT;
    return false;
  }

  raw_t raw = RvaToRaw(stream, stream_size, block_rva);
  if (raw == INVALID_FILE_OFFSET) {
    errno = ERANGE;
    return false;
  }

  IMAGE_EXPORT_DIRECTORY* export_header
    =(IMAGE_EXPORT_DIRECTORY*)(stream + raw);
  raw_t raw_name = RvaToRaw(stream, stream_size, export_header->Name);
  if (raw_name == INVALID_FILE_OFFSET) {
    errno = EINVAL;
    return false;
  }

  strncpy(dll_name, (const char*)((char*)stream + raw_name), bufsize - 1);
  return true;
}

bool EnumExportFunction(
    const char* stream,
    size_t stream_size,
    EXPORT_FUNCTION *exports,
    size_t* bufsize )
{
  if (stream == NULL
   /*|| IsBadReadPtr(stream, stream_size)*/
   || bufsize == NULL
   /*|| IsBadWritePtr(bufsize , sizeof(size_t))*/) {
    errno = EINVAL;
    return false;
  }

  rva_t block_rva
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_EXPORT)->Size;

  //无导出函数
  if (block_rva == 0 ){
    *bufsize = 0;
    return true;
  }

  raw_t block_raw = RvaToRaw(stream, stream_size, block_rva);
  if (block_raw == INVALID_FILE_OFFSET) {
    errno = EINVAL;
    return false;
  }

  IMAGE_EXPORT_DIRECTORY* export_header
    = (IMAGE_EXPORT_DIRECTORY*)(stream + block_raw);
  if (export_header->NumberOfFunctions > 2048){
    errno = EINVAL;
    return false;
  }

  //根据导出函数个数， 计算出所需缓冲区的大小
  if (*bufsize < export_header->NumberOfFunctions * sizeof(EXPORT_FUNCTION)) {
    *bufsize = export_header->NumberOfFunctions * sizeof(EXPORT_FUNCTION);
    errno = EINVAL;
    return false;
  }
  /*
  if (IsBadWritePtr(exports, *bufsize)) {
    errno = EINVAL;
    return false;
  }
  */
  memset(exports, 0, *bufsize);
  *bufsize =  export_header->NumberOfFunctions * sizeof(EXPORT_FUNCTION);

  //获取导出函数名称序号数组
  raw_t raw_name_ordinals
    = RvaToRaw(stream, stream_size, export_header->AddressOfNameOrdinals );
  if (raw_name_ordinals == INVALID_FILE_OFFSET) {
    errno = EINVAL;
    return false;
  }

  //获取导出函数名称数组
  raw_t raw_names
    = RvaToRaw(stream, stream_size, export_header->AddressOfNames);
  if (raw_names == INVALID_FILE_OFFSET) {
    errno = EINVAL;
    return false;
  }

  //获取导出函数地址数组
  raw_t raw_functions
    = RvaToRaw(stream, stream_size, export_header->AddressOfFunctions );
  if (raw_functions == INVALID_FILE_OFFSET) {
    errno = EINVAL;
    return false;
  }

  //先初始化序号和地址
  for(size_t i=0; i < export_header->NumberOfFunctions; i++) {
    exports[i].FunctionVirtualAddress
      = ((va_t*)(stream + raw_functions))[i];
    exports[i].Ordinal = export_header->Base + i;
  }

  //再分析有函数的导出
  for(size_t i = 0; i < export_header->NumberOfNames; i++) {
    int pos = (int)(((unsigned short*)(stream + raw_name_ordinals))[i]);
    rva_t rva = ((rva_t*)(stream + raw_names))[i];

    //可以按照名称进行导出
    raw_t raw = RvaToRaw(stream, stream_size, rva);
    if (raw == INVALID_FILE_OFFSET) {
      continue;
    }

    strncpy(exports[pos].FunctionName,
            stream + raw,
            sizeof(exports[pos].FunctionName) - 1);
  }

  return true;
}

bool EnumImportModuleAndFunction(
    const char* stream,
    size_t stream_size,
    fnEnumImportModuleCallback module_routine,
    void* module_param,
    fnEnumImportFunctionCallback api_routine,
    void* api_param)
{
  if (stream == NULL /*|| IsBadReadPtr(stream, stream_size)*/) {
    errno = EINVAL;
    return false;
  }

  rva_t block_rva
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_IMPORT)->Size;

  if (block_rva == 0 || block_size == 0) {
    //表示没有导入表， 这种情况极少， 但还是存在
    //c:\\windows\\system32\\lz32.dll就是
    errno = ENOENT;
    return false;
  }

  raw_t raw = RvaToRaw(stream, stream_size, block_rva);
  if (raw == INVALID_FILE_OFFSET) {
    errno = ERANGE;
    return false;
  }

  //计算IMAGE_IMPORT_DESCRIPTOR的个数
  IMAGE_IMPORT_DESCRIPTOR* pDescriptor
    = (IMAGE_IMPORT_DESCRIPTOR*)(stream + raw);
  int num_module = 0;
  do {
    //最后一个全零的DESCRIPTOR表示结束
    IMAGE_IMPORT_DESCRIPTOR zero = {0};
    if (0 == memcmp(&pDescriptor[num_module],
                    &zero,
                    sizeof(IMAGE_IMPORT_DESCRIPTOR)))
      break;

    IMAGE_IMPORT_DESCRIPTOR *import_descriptor
      = (IMAGE_IMPORT_DESCRIPTOR*)(stream
                                 + raw
                                 + num_module * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    /*
    if (IsBadReadPtr((char*)import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
      errno = ERANGE;
      break;
    }
    */

    //获取导入模块名称
    raw_t raw_name = RvaToRaw(stream, stream_size, import_descriptor->Name);
    if (raw_name == INVALID_FILE_OFFSET )  {
      errno = ERANGE;
      break;
    }

    /*
    if (IsBadReadPtr((char*)(stream + raw_name), 1)) {
      errno = ERANGE;
      break;
    }
    */

    IMPORT_MODULE module = {0};
    strncpy(module.ModuleName,
            (char*)(stream + raw_name),
            sizeof(module.ModuleName) - 1);
    module.FirstThunk = import_descriptor->FirstThunk;
    module.OriginalFirstThunk = import_descriptor->OriginalFirstThunk;
    module.TimeDataStamp = import_descriptor->TimeDateStamp;
    module.ForwarderChain = import_descriptor->ForwarderChain;
    module.OffsetName = raw_name;

    if (module_routine != NULL) {
      if (!module_routine(&module, module_param)) {
        errno = ECANCELED;
        return false;
      }
    }

    //枚举该模块的导入函数列表
    raw_t raw_thunk = 0;
    rva_t rva_iat = 0;
    if (import_descriptor->OriginalFirstThunk == 0) {
      //OriginalFirstThunk为0， 只能去读FirstThunk的值了
      raw_thunk = RvaToRaw(stream, stream_size, import_descriptor->FirstThunk);
      rva_iat = import_descriptor->FirstThunk;
    } else {
      raw_thunk
        = RvaToRaw(stream, stream_size, import_descriptor->OriginalFirstThunk);
      rva_iat = import_descriptor->FirstThunk;
    }

    if (raw_thunk >= stream_size) {
      errno = ERANGE;
      return false;
    }

    IMAGE_THUNK_DATA* thunks = (IMAGE_THUNK_DATA*)(stream + raw_thunk);
    size_t num_api = 0;
    do {
      //最后一个全零的IMAGE_THUNK_DATA表示结束
      IMAGE_THUNK_DATA zero = {0};
      if (0 == memcmp(&thunks[num_api], &zero, sizeof(IMAGE_THUNK_DATA)))
        break;

      IMPORT_FUNCTION api = {0};
      api.ThunkOffset = (size_t)((char*)&thunks[num_api] - stream);
      api.ThunkRVA
        = RawToRva( stream, raw_thunk + num_api*sizeof(IMAGE_THUNK_DATA));
      api.ThunkValue = thunks[num_api].u1.Function;
      if (thunks[num_api].u1.Ordinal & IMAGE_ORDINAL_FLAG32)  {
        //最高位为1, 表示序号方式导入函数, 函数名称
        api.OffsetName = 0;
        api.FunctionOrdinal
          = (unsigned short)(thunks[num_api].u1.Ordinal & 0x0000FFFF);
      } else  {
        //字符串类型导入函数
        raw_t raw_name
          = RvaToRaw(stream, stream_size, thunks[num_api].u1.AddressOfData);
        if (raw_name == INVALID_FILE_OFFSET) {
          errno = ERANGE;
          continue;
        }

        api.OffsetName = raw_name + sizeof(unsigned short);
        IMAGE_IMPORT_BY_NAME *import_name
          = (IMAGE_IMPORT_BY_NAME*)(stream + raw_name);
        strncpy(api.FunctionName,
                (char*)import_name->Name,
                sizeof(api.FunctionName) - 1);
        api.FunctionHint = (unsigned short)(import_name->Hint);
      }

      api.iat = rva_iat + num_api * sizeof(rva_t);
      if (api_routine != NULL) {
        if (!api_routine(&api, &module, api_param)) {
          errno = ECANCELED;
          return false;
        }
      }
    } while(++num_api);
  }while(++num_module);

  return true;
}

int  GetImportModuleCount(
    const char* stream,
    size_t stream_size)
{
  if (stream == NULL /*|| IsBadReadPtr(stream, stream_size)*/) {
    errno = EINVAL;
    return -1;
  }

  rva_t rva_block
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_IMPORT)->Size;

  raw_t raw = RvaToRaw(stream, stream_size, rva_block);
  if (raw == INVALID_FILE_OFFSET) {
    errno = ERANGE;
    return 0;
  }

  //计算IMAGE_IMPORT_DESCRIPTOR的个数
  IMAGE_IMPORT_DESCRIPTOR* pDescriptor
    = (IMAGE_IMPORT_DESCRIPTOR*)(stream + raw);
  int nCount = 0;
  do {
    //最后一个全零的DESCRIPTOR表示结束
    IMAGE_IMPORT_DESCRIPTOR zero = {0};
    if (0 == memcmp(&pDescriptor[nCount],
                    &zero,
                    sizeof(IMAGE_IMPORT_DESCRIPTOR)))
      break;
  } while(++nCount);

  return nCount;
}

char* GetResourceTypeName(
    int typeOfResource)
{
  switch(typeOfResource)
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

typedef struct _RESROOT
{
  const char*   lpFileData;
  size_t  cbFileSize;
  size_t  ResRootOffset;
}RESROOT;

bool WalkResource(
    RESROOT* root,
    wchar_t* wName,
    short NameLen,
    IMAGE_RESOURCE_DIRECTORY* ResDir,
    RESOURCE_CALLBACK pfnRoutine,
    void* lpParam)
{
  int cRes = ResDir->NumberOfNamedEntries + ResDir->NumberOfIdEntries;
  if (cRes > 512) {
    return true;
  }
  IMAGE_RESOURCE_DIRECTORY_ENTRY* Entry
    = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(ResDir + 1);

  //枚举子资源
  for (int i = 0; i < cRes; i++) {
    //生成新的名称
    wchar_t* NewName = NULL;
    unsigned short NewSize = 0;
    if (Entry[i].NameIsString) {
      if ((root->ResRootOffset + Entry[i].NameOffset) >= root->cbFileSize) {
        continue;
      }

      //有资源名称
      IMAGE_RESOURCE_DIR_STRING_U* pString =
        (IMAGE_RESOURCE_DIR_STRING_U*)(root->lpFileData
                                     + root->ResRootOffset
                                     + Entry[i].NameOffset);
      NewSize = NameLen + pString->Length + sizeof(wchar_t) + sizeof(wchar_t);
      NewName = (wchar_t*)malloc(NewSize);
      memset(NewName, 0, NewSize );
      memcpy(NewName, wName, NameLen);
      NewName[NameLen>>1] = L'\\';
      memcpy((char*)NewName + NameLen + sizeof(wchar_t),
          pString->NameString,
          pString->Length);

    } else {
      char strid[64] = {0};
      if (wName==NULL && NameLen == 0) {
        //资源目录顶层
        char* name = GetResourceTypeName(Entry[i].Id);
        if (name == NULL)
          sprintf(strid, "%d", Entry[i].Id);
        else
          strncpy(strid, name, sizeof(strid) - 1 );
      } else {
        //非资源目录顶层
        sprintf(strid, "%d", Entry[i].Id);
      }

      int id_size = strlen(strid);
      NewSize = NameLen + sizeof(wchar_t) + ( id_size + 1)* sizeof(wchar_t) ;

      NewName = (wchar_t*)malloc(NewSize);
      memset(NewName, 0, NewSize );
      memcpy(NewName, wName, NameLen);
      NewName[NameLen>>1] = L'\\';
    
      int rest = (NewSize - NameLen - sizeof(wchar_t)) / sizeof(wchar_t) -1;
      _mbstowcs( (wchar_t*)((char*)NewName + sizeof(wchar_t) + NameLen), strid, rest);
    }

    if (Entry[i].DataIsDirectory) {
      //资源目录
      //递归
      if (Entry[i].OffsetToDirectory != 0) {
        raw_t raw_dir = root->ResRootOffset + Entry[i].OffsetToDirectory;
        if (raw_dir >= root->cbFileSize) {
          //放弃该资源项
        } else {
          IMAGE_RESOURCE_DIRECTORY* subdir =
            (IMAGE_RESOURCE_DIRECTORY*)(root->lpFileData + raw_dir);
          if (!WalkResource(root, NewName, NewSize, subdir, pfnRoutine, lpParam)) {
            //用户取消递归
            free(NewName);
            NewName = NULL;
            return false;
          }
        }
      }
    } else {
      //资源数据
      if (Entry[i].OffsetToData + root->ResRootOffset < root->cbFileSize) {
        IMAGE_RESOURCE_DATA_ENTRY* data_entry =
          (IMAGE_RESOURCE_DATA_ENTRY*)(root->lpFileData
                                       + root->ResRootOffset
                                       + Entry[i].OffsetToData);
        if (!pfnRoutine(NewName, NewSize, data_entry, lpParam)) {
          free(NewName);
          NewName = NULL;
          return false;
        }
      }
    }

    free(NewName);
    NewName = NULL;
  }

  return true;
}

bool EnumResource(
    const char* stream,
    size_t stream_size,
    RESOURCE_CALLBACK pfnRoutine,
    void* lpParam)
{
  if (stream == NULL
   /*|| IsBadReadPtr(stream, stream_size)*/
   || pfnRoutine == NULL) {
    errno = EINVAL;
    return false;
  }

  rva_t block_rva
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress;
  size_t block_size
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_RESOURCE)->Size;

  if (block_rva == 0) {
    return true;
  }

  raw_t raw = RvaToRaw(stream, stream_size, block_rva );
  if (raw == INVALID_FILE_OFFSET) {
    errno = ERANGE;
    return false;
  }

  IMAGE_RESOURCE_DIRECTORY* pRootDirectory
    = (IMAGE_RESOURCE_DIRECTORY*)(stream + raw);
  RESROOT resroot = {0};
  resroot.lpFileData = stream;
  resroot.cbFileSize = stream_size;
  resroot.ResRootOffset = raw;
  if (!WalkResource(&resroot, NULL, 0, pRootDirectory, pfnRoutine, lpParam)) {
    //用户取消递归
    errno = ECANCELED;
    return false;
  }

  return true;
}

bool EnumRelocation(
    const char* stream,
    size_t stream_size,
    RELOC_BLOCK_CALLBACK block_routine,
    void* lpBlockParam,
    RELOC_ITEM_CALLBACK item_routine,
    void* lpItemParam )
{
  if (stream == NULL /*|| IsBadReadPtr(stream, stream_size)*/) {
    errno = EINVAL;
    return false;
  }

  if (block_routine != NULL /*&& IsBadCodePtr((FARPROC)block_routine)*/) {
    errno = EINVAL;
    return false;
  }

  if (item_routine != NULL /*&& IsBadCodePtr((FARPROC)item_routine)*/) {
    errno = EINVAL;
    return false;
  }

  rva_t block_rva
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress;
  size_t blook_size
    = DIRECTORY_ENTRY(stream, IMAGE_DIRECTORY_ENTRY_BASERELOC)->Size;

  if (block_rva == 0)
    return true;

  raw_t raw = RvaToRaw(stream, stream_size, block_rva);
  if (raw == INVALID_FILE_OFFSET) {
    errno = ERANGE;
    return false;
  }

  IMAGE_BASE_RELOCATION *base_relocation
    = (IMAGE_BASE_RELOCATION*)((char*)stream + raw);

  //获取重定位项的总数
  while(base_relocation->SizeOfBlock != 0) {
    PE_RELOCATION_BLOCK block = {0};
    block.rva = base_relocation->VirtualAddress;
    block.cItem = (base_relocation->SizeOfBlock
                 - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short);
    if (block_routine != NULL) {
      if (!block_routine(&block, lpBlockParam)) {
        errno = ECANCELED;
        return false;
      }
    }

    if (item_routine != 0) {
      unsigned short* items = (unsigned short*)(base_relocation + 1);
      for (int i=0; i < block.cItem ; i++) {
        PE_RELOCATION_ITEM Item = {0};
        Item.rva = (items[i] & 0x0FFF) + base_relocation->VirtualAddress;;
        Item.Type = ((items[i] & 0x0000F000) >> 12);

        if (Item.Type == IMAGE_REL_BASED_ABSOLUTE) {
          //对齐用， 没实际作用
          Item.rva = 0;
        }

        if (!item_routine(block.rva, &Item, lpItemParam)) {
          errno = ECANCELED;
          return false;
        }
      }
    }

    //下一个Relocation Block
    base_relocation
      = (IMAGE_BASE_RELOCATION*)((char*)base_relocation
                               + base_relocation->SizeOfBlock);
  }

  return true;
}

bool EnumBound(
    const char* stream,
    size_t stream_size,
    PPE_BOUND pBounds,
    size_t* pcbSize)
{
  if (stream == NULL /*|| IsBadReadPtr(stream, stream_size)*/) {
    //SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  if (pcbSize == NULL /*|| IsBadWritePtr(pcbSize , sizeof(size_t))*/) {
    //SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }

  rva_t block_rva
    = GET_NT_HEADER(stream)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
  rva_t block_size
    = GET_NT_HEADER(stream)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
  if (block_rva >= stream_size) {
    //SetLastError(ERROR_BAD_EXE_FORMAT);
    return false;
  }

  if (block_rva == 0) {
    *pcbSize = 0;
    return true;
  }

  IMAGE_BOUND_IMPORT_DESCRIPTOR *descriptor
    = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(stream + block_rva);
  int cBound = 0;
  while(descriptor->OffsetModuleName != 0) {
    cBound ++;
    descriptor = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)( (char*)descriptor
                       + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR)
                       + descriptor->NumberOfModuleForwarderRefs
                       * sizeof(IMAGE_BOUND_FORWARDER_REF));
  }

  if (*pcbSize < cBound * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR)) {
    *pcbSize = cBound * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
    //SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return false;
  }

  /*
  if (IsBadWritePtr(pBounds, *pcbSize)) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return false;
  }
  */

  memset(pBounds, 0, *pcbSize);
  *pcbSize = cBound * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

  descriptor = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(stream + block_rva);

  cBound = 0;
  while(descriptor->OffsetModuleName != 0) {
    pBounds[cBound].TimeDateStamp = descriptor->TimeDateStamp;
    pBounds[cBound].NumberOfModuleForwarderRefs
      = descriptor->NumberOfModuleForwarderRefs;
    strncpy(pBounds[cBound].ModuleName,
            (char*)stream + block_rva + descriptor->OffsetModuleName,
            sizeof(pBounds[cBound].ModuleName) - 1);
    descriptor = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)((char*)descriptor
                          + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR)
                          + descriptor->NumberOfModuleForwarderRefs
                          * sizeof(IMAGE_BOUND_FORWARDER_REF));
    cBound++;
  }

  return true;
}

//计算虚拟地址所在的节
int GetSectionIndexByRva(
    const char* stream,
    rva_t rva)
{
  if (stream == NULL || rva == INVALID_VIRTUAL_ADDRESS) {
    errno = EINVAL;
    return -1;
  }

  //枚举所有Section
  IMAGE_NT_HEADERS* nt_header = GET_NT_HEADER(stream);
  unsigned int section_align_mask
    = nt_header->OptionalHeader.SectionAlignment - 1;
  unsigned int file_align = nt_header->OptionalHeader.FileAlignment;
  unsigned int file_align_mask = file_align - 1;

  int i=0;
  for(; i < nt_header->FileHeader.NumberOfSections; i++)  {
    //判断RVA是否在该Section地址范围内
    IMAGE_SECTION_HEADER section = {0};
    GetSectionHeader(stream, i, &section);
    if ((rva >= section.VirtualAddress)
     && (rva <= (section.VirtualAddress + section.Misc.VirtualSize - 1)))
      break;
  }

  if (i >= nt_header->FileHeader.NumberOfSections)
    return -1;
  else
    return i;
}

//计算文件偏移所在的节
int  GetSectionIndexByRaw(
    const char* stream,
    raw_t raw)
{
  if (stream == NULL)
    return -1;

  rva_t rva = RawToRva(stream, raw);
  if (rva == INVALID_VIRTUAL_ADDRESS)
    return -1;

  return GetSectionIndexByRva(stream, rva);
}

bool GetSectionHeader(
  const char* stream,
  int section_index,
  IMAGE_SECTION_HEADER *section_header)
{
  //由于脱壳的需要， 有的时候是不知道文件数据大小的
  /*
  if (lpFileData == NULL || IsBadReadPtr(lpFileData, cbFileSize)) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }
  */

  if (section_header == NULL
    /*|| IsBadWritePtr(section_header, sizeof(IMAGE_SECTION_HEADER))*/) {
    errno = EINVAL;
    return false;
  }

  IMAGE_NT_HEADERS* nt_header = GET_NT_HEADER(stream);
  if (section_index >= nt_header->FileHeader.NumberOfSections) {
    errno = EINVAL;
    return false;
  }
  memcpy(section_header,
         GET_SECTION_HEADER(nt_header, section_index),
         sizeof(IMAGE_SECTION_HEADER));
  return true;
}

//获取附加数据的位置和长度
bool GetOverlay(
    const char* stream,
    size_t stream_size,
    raw_t* overlay_raw,
    size_t* overlay_len)
{
  IMAGE_NT_HEADERS* nt_header = GET_NT_HEADER(stream);
  //将所有的节的长度进行累加
  size_t image_size = 0;
  for(int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER section = {0};
    GetSectionHeader(stream, i, &section);
    image_size += ALIGN(section.SizeOfRawData,
                        nt_header->OptionalHeader.FileAlignment);
  }
  image_size += nt_header->OptionalHeader.SizeOfHeaders;

  if (image_size > stream_size) {  //损坏的PE
    *overlay_raw = 0;
    *overlay_len = 0;
    return true;
  }

  if (image_size == stream_size) { //没有附加数据
    *overlay_raw = 0;
    *overlay_len = 0;
    return true;
  } else {
    *overlay_raw = image_size;
    *overlay_len = stream_size - image_size;
    return true;
  }
}



#pragma pack(push)
#pragma pack(2)

typedef struct _ICON_ENTRY
{
  BYTE  bWidth;
  BYTE  bHeigh;
  BYTE  bColorCount;      //Number of colors in image(0 if>=8bpp)
  BYTE  bReserved;
  WORD  wPlanes;          //color planes
  WORD  wBitCount;        //bits per pixel
  DWORD dwBytesInRes;
  DWORD dwImageOffset;    //where in the file is this image
}ICON_ENTRY;

typedef struct _ICON_DIR
{
  WORD    idReserved;
  WORD    idType;
  WORD    idCount;
  ICON_ENTRY idEntries[1];
}ICON_DIR;

typedef struct _GRPICON_DIR_ENTRY
{
  BYTE  bWidth;
  BYTE  bHeigh;
  BYTE  bColorCount;
  BYTE  bReserved;
  WORD  wPlanes;
  WORD  wBitCount;
  DWORD dwBytesInRes;
  WORD  nID;
}GRPICON_DIR_ENTRY;

typedef struct _GRPICONDIR
{
  WORD    idReserved;
  WORD    idType;
  WORD    idCount;
  GRPICON_DIR_ENTRY idEntries[1];
}GRPICONDIR;

#pragma pack(pop)

typedef struct _PE_RES_FINDER
{
  rva_t   rva;
  size_t  size;
  int     idres;
}PE_RES_FINDER;

bool EnumIconGroupsRoutine(
    wchar_t* wName,
    unsigned short NameLen,
    IMAGE_RESOURCE_DATA_ENTRY* DataEntry,
    void* lpParam )
{
  if (wcsncmp( wName, L"\\GROUP_ICON\\", wcslen(L"\\14\\")) == 0 ) {
    PE_RES_FINDER* icon = (PE_RES_FINDER*)lpParam;
    icon->rva = DataEntry->OffsetToData;
    icon->size = DataEntry->Size;
    return false;
  }

  return true;
}

bool EnumIconRoutine(
    wchar_t* wName,
    unsigned short NameLen,
    IMAGE_RESOURCE_DATA_ENTRY* DataEntry,
    void* lpParam )
{
  PE_RES_FINDER* icon = (PE_RES_FINDER*)lpParam;
  wchar_t resname[16] = {0};
  _snwprintf( (wchar_t*)resname, 16 - 1, L"\\ICON\\%d\\", icon->idres );
  //printf("%S==%S\t", resname, wName);
  if (wcsncmp( wName, resname, wcslen(resname)) == 0 ) {
    //printf("TRUE\n");
    icon->rva = DataEntry->OffsetToData;
    icon->size = DataEntry->Size;
    return false;
  }
  //printf("FALSE\n");
  return true;
}

bool GetIcon(
    const char* stream,
    size_t stream_size,
    const char* ico_file)
{
  PE_RES_FINDER icon_group = {0};
  bool is_success = false;

  //遍历资源, 找到ICON GROUPS资源
  EnumResource(stream, stream_size, EnumIconGroupsRoutine, &icon_group );
  if (icon_group.rva == 0 && icon_group.size == 0 ) {
    //printf("ico group not found");
    return false;
  }

  raw_t raw = RvaToRaw(stream, stream_size, icon_group.rva );
  if (raw == INVALID_FILE_OFFSET) {
    //printf("invalid icon group raw");
    return false;
  }

  GRPICONDIR* icon_dir = (GRPICONDIR*)(stream+raw);
  if (icon_group.size != sizeof(GRPICONDIR)
                         + (icon_dir->idCount-1)*sizeof(GRPICON_DIR_ENTRY)) {
    //printf("invalid icon group size");
    return false;
  }

  FILE* fp = fopen( ico_file, "wb");
  if (fp==NULL) {
    //printf("open file fail");
    return false;
  }

  size_t ico_header_size = sizeof(GRPICONDIR)
                           + (icon_dir->idCount-1)*sizeof(ICON_ENTRY);
  ICON_DIR* ico_header = (ICON_DIR*)malloc(ico_header_size);
  if (ico_header == NULL) {
    //printf("malloc memory failed");
    is_success = false;
    goto ret_door;
  }

  fseek(fp, ico_header_size, SEEK_SET);
  for (int i=0; i<icon_dir->idCount; i++) {
    ico_header->idEntries[i].bWidth = icon_dir->idEntries[i].bWidth;
    ico_header->idEntries[i].bHeigh = icon_dir->idEntries[i].bHeigh;
    ico_header->idEntries[i].bColorCount = icon_dir->idEntries[i].bColorCount;
    ico_header->idEntries[i].bReserved = icon_dir->idEntries[i].bReserved;
    ico_header->idEntries[i].wPlanes = icon_dir->idEntries[i].wPlanes;
    ico_header->idEntries[i].wBitCount = icon_dir->idEntries[i].wBitCount;

    //获取资源的位置和长度
    PE_RES_FINDER finder = {0};
    finder.idres = icon_dir->idEntries[i].nID;
    EnumResource(stream, stream_size, EnumIconRoutine, &finder);
    if (finder.size != 0) {
      raw_t icon_raw = RvaToRaw(stream, stream_size, finder.rva );
      if (icon_raw != INVALID_FILE_OFFSET) {
        //write ico data
        if (finder.size != fwrite(stream+icon_raw, 1, finder.size, fp)){
          //printf("write ico data failed");
          is_success = false;
          goto ret_door;
        }
        ico_header->idEntries[i].dwBytesInRes = finder.size;
        ico_header->idEntries[i].dwImageOffset = ftell(fp) - finder.size;
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

int EnumSectionGap(
    const char* stream,
    size_t stream_size,
    SECTION_GAP* pSectionGaps,
    size_t cbSize)
{
  int cMaxGap = cbSize / sizeof(SECTION_GAP);
  IMAGE_DOS_HEADER *dos_header = GET_DOS_HEADER(stream);
  IMAGE_NT_HEADERS *nt_header = GET_NT_HEADER(stream);
  size_t dwActualHeaderSize = dos_header->e_lfanew
                + sizeof(int)
                + sizeof(IMAGE_FILE_HEADER)
                + nt_header->FileHeader.SizeOfOptionalHeader
                + nt_header->FileHeader.NumberOfSections
                * sizeof(IMAGE_SECTION_HEADER);

  int cGap = 0;
  if (dwActualHeaderSize != nt_header->OptionalHeader.SizeOfHeaders) {
    pSectionGaps[cGap].offset = dwActualHeaderSize;
    pSectionGaps[cGap].length = nt_header->OptionalHeader.SizeOfHeaders
                              - dwActualHeaderSize;
  }
  cGap++;

  for (int i= 0;
     i < nt_header->FileHeader.NumberOfSections && cGap < cMaxGap ;
     i++ ) {
    IMAGE_SECTION_HEADER Header = {0};
    GetSectionHeader(stream, i, &Header);

    if (Header.Misc.VirtualSize < Header.SizeOfRawData) {
      pSectionGaps[cGap].offset = Header.PointerToRawData
                                + Header.Misc.VirtualSize;
      pSectionGaps[cGap].length = Header.SizeOfRawData
                                - Header.Misc.VirtualSize;
      cGap++;
    }
  }

  return cGap * sizeof(SECTION_GAP);
}

bool RemoveLastSection(
    char* stream)
{
  IMAGE_NT_HEADERS* nt_header = GET_NT_HEADER(stream);
  IMAGE_SECTION_HEADER Header = {0};
  if (!GetSectionHeader(stream,
               nt_header->FileHeader.NumberOfSections -1,
               &Header))
    return false;

  //删除节数据
  memset(stream + Header.PointerToRawData, 0, Header.SizeOfRawData);

  //删除节描述符
  IMAGE_SECTION_HEADER* pSectionHeader =
    (IMAGE_SECTION_HEADER*)((char*)nt_header
                 + sizeof(int)
                 + sizeof(IMAGE_FILE_HEADER)
                 + nt_header->FileHeader.SizeOfOptionalHeader);
  memset(pSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));

  //修改节数量
  nt_header->FileHeader.NumberOfSections --;

  //修改SizeOfImage字段
  nt_header->OptionalHeader.SizeOfImage
    -= ALIGN(Header.Misc.VirtualSize,
             nt_header->OptionalHeader.SectionAlignment);
  return true;
}

#if (defined(__MINGW32__) || defined(__MSC_VER__))
bool QueryValue(
    const char* szQuery,
    LPVOID pBlock,
    char* lpszValue,
    DWORD cbValueSize)
{
  LPVOID pValueInBlock = NULL;
  UINT nLen = 0;
  if( !VerQueryValue( pBlock, (char*)szQuery, (LPVOID*)&pValueInBlock, &nLen ))
    return false;

  //缓冲区足够
  strncpy( lpszValue, (char*)pValueInBlock, (cbValueSize - 1) < nLen ? ( cbValueSize - 1 ): nLen  );
  return true;
}
#endif

bool GetVersionInfo(
    const char* filename,
    PE_VERSION *verinfo)
{
#if (defined(__MINGW32__) || defined(__MSC_VER__))
  //检验参数
  if (filename == NULL /*|| IsBadStringPtr( filename, -1)*/) {
    //SetLastError( ERROR_INVALID_PARAMETER );
    return false;
  }

  if (verinfo == NULL /*|| IsBadWritePtr( verinfo, sizeof(PE_VERSION))*/) {
    //SetLastError( ERROR_INVALID_PARAMETER );
    return false;
  }

  DWORD dwHandle = 0;
  DWORD dwInfoSize = 0;
  if (0 == (dwInfoSize = GetFileVersionInfoSize(filename,  &dwHandle)))
    return false;

  LPVOID pData = (LPVOID)malloc(dwInfoSize);
  if( pData == NULL ) {
    //SetLastError( ERROR_NOT_ENOUGH_MEMORY );
    return false;
  }
  memset(pData, 0, dwInfoSize);

  //获取文件信息块
  if( 0 == GetFileVersionInfo(filename, 0, dwInfoSize, pData)) {
    free(pData);
    pData = NULL;
    return false;
  }

  struct LANGANDCODEPAGE  {
    WORD wLanguage;
    WORD wCodePage;
  };

  UINT  nLen = 0;
  LANGANDCODEPAGE *pTranslate = NULL;
  if(!VerQueryValue(pData, "\\VarFileInfo\\Translation",
                    (LPVOID*)&pTranslate, &nLen)) {
    free(pData);
    pData = NULL;
    return false;
  }
  verinfo->wLanguage = pTranslate->wLanguage;
  verinfo->wCodePage = pTranslate->wCodePage;

  //获取文件名称
  char  szQuery[64] = {0};
  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\FileVersion",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue( szQuery, pData, verinfo->FileVersion,
    sizeof( verinfo->FileVersion ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\CompanyName",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue( szQuery, pData, verinfo->CompanyName,
    sizeof( verinfo->CompanyName ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\FileDescription",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue( szQuery, pData, verinfo->FileDescription,
    sizeof( verinfo->FileDescription ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\ProductName",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue(szQuery, pData, verinfo->ProductName,
    sizeof( verinfo->ProductName ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\LegalCopyright",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue(szQuery, pData, verinfo->LegalCopyright,
    sizeof( verinfo->LegalCopyright ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\InternalName",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue(szQuery, pData, verinfo->InternalName,
    sizeof( verinfo->InternalName ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\Comments",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue(szQuery, pData, verinfo->Comments,
    sizeof( verinfo->Comments));

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\SpecialBuild",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue(szQuery, pData, verinfo->SpecialBuild,
    sizeof( verinfo->SpecialBuild ) );

  _snprintf(szQuery,
            sizeof(szQuery)-1,
            "\\StringFileInfo\\%04x%04x\\LegalTrademarks",
            pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue(szQuery,
              pData,
              verinfo->LegalTrademarks,
              sizeof( verinfo->LegalTrademarks ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
    "\\StringFileInfo\\%04x%04x\\PrivateBuild",
    pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue( szQuery, pData, verinfo->PrivateBuild,
    sizeof( verinfo->PrivateBuild ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
            "\\StringFileInfo\\%04x%04x\\ProductVersion",
            pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue( szQuery, pData, verinfo->ProductVersion,
              sizeof( verinfo->ProductVersion ) );

  _snprintf(szQuery, sizeof(szQuery)-1,
            "\\StringFileInfo\\%04x%04x\\OriginalFilename",
            pTranslate->wLanguage, pTranslate->wCodePage );
  QueryValue(szQuery,
             pData,
             verinfo->OriginalFilename,
             sizeof(verinfo->OriginalFilename));

  free(pData);
  pData = NULL;
  return true;
#else
  return false;
#endif 
}

bool LoadPERelocRoutine(
    rva_t rvaOwnerBlock,
    PPE_RELOCATION_ITEM pItem,
    void* lpParam )
{
  char* image = (char*)lpParam;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)image;
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
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)image;

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
  //*(rva_t*)(image + pImportFunction->ThunkRVA) = addr;
  return true;
#endif
}

bool LoadPEImage(const char* stream, size_t stream_size, char* image, size_t image_size)
{
#ifdef __GNUC__
  return false;
#else

  IMAGE_NT_HEADERS *nt = GET_NT_HEADER(stream);
  if (image_size < nt->OptionalHeader.SizeOfImage){
    return false;
  }

  //load pe headers
  memcpy(image, stream, nt->OptionalHeader.SizeOfHeaders);

  IMAGE_NT_HEADERS *image_nt = GET_NT_HEADER(image);

  //load all sections
  for (int i=0; i < nt->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER *section = GET_SECTION_HEADER(nt,i);
    memcpy(image+section->VirtualAddress,
             stream+section->PointerToRawData,
             section->SizeOfRawData );
    IMAGE_SECTION_HEADER *image_section = GET_SECTION_HEADER(image_nt,i);
    image_section->SizeOfRawData = ALIGN(section->SizeOfRawData,
                                          nt->OptionalHeader.SectionAlignment);
    image_section->PointerToRawData = section->VirtualAddress;
  }

  //reloc
  if (!EnumRelocation(stream, stream_size, NULL, NULL, LoadPERelocRoutine, image)) {
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
  //image_nt->OptionalHeader.ImageBase = (DWORD)image;

  //modify FileAlignment
  image_nt->OptionalHeader.FileAlignment = nt->OptionalHeader.SectionAlignment;

  return true;
#endif
}
