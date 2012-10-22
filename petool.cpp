// pefile.cpp : Defines the entry point for the console application.
//
#pragma  warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <filemap.h>
#include "petype.h"
#include "pe.h"

void WalkResource(int pe, IMAGE_RESOURCE_DIRECTORY_ENTRY* parent, char* prefix )
{
    IMAGE_RESOURCE_DIRECTORY_ENTRY* res = pe_resource_first(pe, parent);
    for (; res != NULL; res = pe_resource_next(res)) {
      if (res->NameIsString) {
        char name[256] = {0};
        pe_resource_name(pe, res, name, sizeof(name) - 1);
        printf("%s%s", prefix, name);
      } else {
        printf("%s%d", prefix, res->Id);
      }

      if (IS_RESOURCE_DIRECTORY(res)) {
        printf("\n");
        char prefix2[512] = {0};
        strncpy(prefix2, prefix, strlen(prefix));
        strcat(prefix2, "\t");
        WalkResource(pe, res, prefix2);
      } else{
        IMAGE_RESOURCE_DATA_ENTRY* data = pe_resource_data(pe, res);
        if (data == NULL) {
          continue;
        }

        printf( "  Offset:0x%08x\tSize:0x%08X\n",
          (unsigned int)data->OffsetToData, 
          (unsigned int)data->Size);
      }
    }
}

void show_usage()
{
  printf( "example.exe <file>\n");
  /*
  printf("-overlay\n");
  printf("-section\n");
  printf("-export\n");
  printf("-import\n");
  printf("-entry\n");
  printf("-gap\n");
  printf("-resource\n");
  printf("-version\n");
  printf("-icon <ico_file>\n");
  printf("-loadimage <dump_file>\n");
  */
}

void dump_overlay(int pe)
{
  //dump附加数据
  raw_t overlay_offset = 0;
  size_t overlay_size = 0;
  IMAGE_OVERLAY* overlay = pe_overlay(pe);

  if(overlay == NULL){
    printf( "get overlay failed\n" );
  } else {
    printf( "Overlay  Offset:0x%08X Size:0x%08X\n",
            overlay->offset_in_file,
            overlay->size );
  }
}

void dump_section(int pe)
{
  //dump节表
  IMAGE_NT_HEADERS* nt = pe_nt_header(pe);
  WORD i = 0;
  for( ; i < nt->FileHeader.NumberOfSections; i++ ) {
    IMAGE_SECTION_HEADER header;
    memset(&header, 0, sizeof(IMAGE_SECTION_HEADER));
    if( copy_section_header(pe, i, &header)) {
      printf( "%-8s\t%08X\t%08X\t%08X\t%08X",
        header.Name,
        (unsigned int)header.VirtualAddress,
        (size_t)header.Misc.VirtualSize, 
        (unsigned int)header.PointerToRawData,
        (unsigned int)header.SizeOfRawData );
    }
  }  
}

void dump_export(int pe)
{
  //dump导出表
  const char* DllName = pe_export_dllname(pe);
  if (DllName == NULL) {
    printf("DllName: NULL\n");
  } else {
    printf( "DllName:%s\n", DllName );
  }

  IMAGE_EXPORT_FUNCTION* api = pe_export_first(pe);
  for(; api != NULL; api = pe_export_next(api)) {
      printf( "EXPORT: Oridinal=%d, Address=0x%08X, Name=%s\n",
        api->Ordinal, 
        api->FunctionVirtualAddress,
        api->FunctionName );
  } 
}

void dump_import(int pe)
{
  //dump导入表
  IMAGE_IMPORT_DESCRIPTOR* dll = pe_import_dll_first(pe);
  for (; dll != NULL; dll = pe_import_dll_next(dll)) {
    char dllname[256] = {0};
    pe_import_dllname(pe, dll, dllname, sizeof(dllname)-1);
    printf("%s\n", dllname);
    
    IMAGE_IMPORT_FUNCTION* api = pe_import_api_first(dll);
    for (; api != NULL; api = pe_import_api_next(api) ) {
      printf("\t\t0x%08X\t%s\n", api->OffsetName, api->FunctionName); 
    }
  } 
}

void dump_entry(int pe)
{
    //dump入口点
    IMAGE_NT_HEADERS* nt = pe_nt_header(pe);
    rva_t rva = nt->OptionalHeader.AddressOfEntryPoint;
    //计算入口点在第几个节中
    int iSection = pe_section_by_rva(pe, rva);

    printf( "[ENTRY RVA]=%08X,[ENTRY SECTION]=%d\n", rva, iSection); 
}

void dump_icon(int pe,const char* ico_file)
{
    printf("Icon File: %s\n", ico_file);
    if( !pe_icon_file(pe, ico_file)) {
      printf("GetIcon failed");
    } else {
      printf("GetIcon successed");
    } 
}

void dump_resource(int pe)
{
    char prefix[512] = {0};
    WalkResource(pe, NULL, prefix); 
}

void dump_version(int pe)
{
  //dump版本信息
  IMAGE_VERSION* version = pe_version_first(pe);
  for (; version != NULL; version = pe_version_next(version)) {
    printf("%S: %S\n", version->name, version->value);
  }    
}

int main(int argc, char* argv[])
{
  if (argc!=2) {
    show_usage();
    return 0;
  }

  while(true) {
  MAPPED_FILE view = {0};
  if( 0 != map_file( argv[1], &view ) ) {
    printf( "open file failed: %s\n", argv[2]);
    return -1;
  }


  int pe = pe_open((const char*)view.data, view.size);
  if (pe == INVALID_PE) {
    printf( "file is not pe format");
    return -1;
  }

  dump_entry(pe);
  dump_version(pe);
  dump_section(pe);
  dump_export(pe);
  dump_import(pe);
  dump_overlay(pe);
  dump_resource(pe);

  char path[256] = {0};
  getcwd(path, sizeof(path) - 1);
  strcat(path, "\\sample.ico");
  dump_icon(pe, path);

  pe_close(pe);

  unmap_file(&view);
  }
 
  system("pause");
  return 0;
}





