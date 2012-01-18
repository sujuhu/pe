// pefile.cpp : Defines the entry point for the console application.
//
#pragma  warning(disable:4996)
#include <windows.h>
#include <fstream>
#include <string>
#include "libpe.h"
#include "base/filemap.h"
#include <vector>
using namespace std;

/*
typedef struct _COMPILER
{
  string name;
  string sign;
}COMPILER;

bool match_compiler( COMPILER* compile, FILE_VIEW* view )
{
  //将字符串转换成二进制数据
  int nLen = compile->sign.size();
  int nbyte = nLen >> 1;
  unsigned char* buffer = (unsigned char*)malloc( nbyte );
  memset( buffer, 0, nbyte );
  unsigned char* ignore = (unsigned char*)malloc( nbyte );
  memset( ignore, 0, nbyte );

  int i = 0;
  for( i=0; i < ( nLen / 2) &&  i < (int)nbyte ; i++ ) {
    char szTmp[3] = {0};
    strncpy( szTmp, compile->sign.c_str() + i*2, 2 );
    if ( strcmp( szTmp, "??" )==0 ){
      buffer[i] = 0x00;
      ignore[i] = 1;
    } else {
      buffer[i] = (BYTE)strtoul( szTmp, NULL, 16 );
    }
  }

  //获取入口点
  IMAGE_NT_HEADERS* nt = GET_NT_HEADER( view->lpData );
  DWORD va = nt->OptionalHeader.AddressOfEntryPoint
             + nt->OptionalHeader.ImageBase;
  DWORD raw = GetFileOffSet( view->lpData, va, view->SizeOfFile );

  //每个字节进行匹配
  bool matched = true;
  for(  i = 0; i < nbyte; i++ ) {
    if( ignore[i] == 1 ) {
      //通配符号
      continue;
    } else {
      if ( buffer[i] == *( unsigned char *)((char*)view->lpData + raw + i) ) {
        continue;
      } else {
        matched = false;
        break;
      }
    }
  }

  free( buffer );
  buffer = NULL;
  free( ignore );
  ignore = NULL;

  return matched;
}


bool doscan(char* sample_file, char* dbfile, char* compiler_name, int bufsize)
{
  //打开数据库文件
  ifstream ifs;
  ifs.open( dbfile, ios::in | ios::_Nocreate );
  if( ifs.bad() ) {
    printf( "Sign File Failed\n" );
    return false;
  }

  vector<COMPILER> ctCompiler;
  string line;
  while( ::getline( ifs, line ) ) {
    //解析行数据
    regex::match_results results;
    regex::rpattern partten( "^(.+)=(.+)$" );
    // Match a dollar sign followed by one or more digits,
    // optionally followed by a period and two more digits.
    // The double-escapes are necessary to satisfy the compiler.
    regex::match_results::backref_type br = partten.match( line, results );
    if( br.matched ) {
      COMPILER  compile;
      compile.name = results.backref(1).str();
      compile.sign = results.backref(2).str();
      ctCompiler.push_back( compile );
    } else {
      //一个都没找到
      continue;
    }
  }

  ifs.close();

  MAPPED_FILE  view = {0};
  if( !map_file( sample_file, &view ) ) {
    printf( "open file view failed" );
    return false;
  }

  //进行匹配
  std::vector<COMPILER>::iterator it = ctCompiler.begin();
  for( ; it != ctCompiler.end(); it++ ) {
    if( match_compiler( &(*it), &view ) ) {
      strncpy( compiler_name, it->name.c_str(), bufsize - 1  );
      unmap_file( &view );
      return true;
    }
  }
  unmap_file( &view );
  return false;
}

*/

typedef struct _RESITEM
{
  string name;
  DWORD  offset;
  DWORD  size;
  DWORD  codepage;
}RESITEM;

bool ResourceRoutine(
    wchar_t* wName,
    unsigned short NameLen,
  IMAGE_RESOURCE_DATA_ENTRY* DataEntry,
    void* lpParam )
{
  vector<RESITEM>* ctItem = (vector<RESITEM>*)lpParam;
  RESITEM item;
  char* name = (char*)malloc( (NameLen >> 1) + 1 );
  memset( name, 0, (NameLen >> 1) + 1  );
  wcstombs( name, wName, (NameLen >> 1) );
  item.name = name;
  item.offset = DataEntry->OffsetToData;
  item.size = DataEntry->Size;
  item.codepage = DataEntry->CodePage;
  ctItem->push_back( item );
  free( name );
  name = NULL;
  return TRUE;
}

BOOL WalkRes( MAPPED_FILE* view, vector<RESITEM>* ctItem )
{
  if( !EnumResource( (const char*)view->data,
                     view->size,
                     ResourceRoutine,
                     (LPVOID)ctItem ) ) {
    return FALSE;
  }

  return TRUE;
}

//枚举导入模块回调函数
bool ImportModuleCallback( PIMPORT_MODULE pImportModule, void* lpParam )
{
  //printf( "[MODULE]%s\n", pImportModule->ModuleName );
  return TRUE;
}

//枚举导入函数回调函数
bool ImportFunctionRoutine( PIMPORT_FUNCTION pImportFunction,
               PIMPORT_MODULE pImportModule, void* lpParam )
{
  printf( "[%s:0x%08X]%s:0x%08X\n",
          pImportModule->ModuleName,
          pImportModule->OffsetName,
          pImportFunction->FunctionName,
          pImportFunction->OffsetName );
  return TRUE;
}

void show_usage()
{
  printf( "example.exe <file> -<item>\n");
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
}

int main(int argc, char* argv[])
{
  if ( argc!=3 && argc!=4 ) {
    show_usage();
    return 0;
  }

  MAPPED_FILE view = {0};
  if( 0 != map_file( argv[2], &view ) ) {
    printf( "open file failed\n" );
    return 0;
  }

  if( strcmp( argv[1], "-overlay" ) == 0 ) {
    //dump附加数据
    raw_t overlay_offset = 0;
    size_t overlay_size = 0;
    if( !GetOverlay( (const char*)view.data,
                     view.size,
                     &overlay_offset,
                     &overlay_size ) ) {
      printf( "get overlay failed\n" );
    } else {
      printf( "Overlay  Offset:0x%08X Size:0x%08X\n",
              overlay_offset,
              overlay_size );
    }

  } else if( strcmp( argv[1], "-section" ) == 0 ){
    //dump节表
    IMAGE_NT_HEADERS* nt = GET_NT_HEADER( view.data );
    WORD i = 0;
    for( ; i < nt->FileHeader.NumberOfSections; i++ ) {
      IMAGE_SECTION_HEADER header = {0};
      if( GetSectionHeader((const char*)view.data, i, &header ) )
        printf( "%-8s\t%08X\t%08X\t%08X\t%08X",
                header.Name,
                header.VirtualAddress,
        header.Misc.VirtualSize, header.PointerToRawData,
        header.SizeOfRawData );
    }
  } else if( strcmp( argv[1], "-export" ) == 0 ) {
    //dump导出表
    char DllName[256] = {0};
    if( GetExportDllName((const char*)view.data,
                         view.size,
                         DllName,
                         sizeof( DllName )) ) {
      printf( "DllName:%s\n", DllName );
    }
    size_t size = 0;
    EnumExportFunction( (const char*)view.data, view.size, NULL, &size );
    if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER ) {
      EXPORT_FUNCTION* exports = (EXPORT_FUNCTION*)malloc( size );
      memset( exports, 0, size );
      if( EnumExportFunction((const char*)view.data,
                             view.size,
                             exports,
                             &size ) ) {
        DWORD i = 0;
        for( ; i < size / sizeof( EXPORT_FUNCTION ); i++ ) {
          printf( "EXPORT: Oridinal=%d, Address=0x%08X, Name=%s\n",
            exports[i].Ordinal, exports[i].FunctionVirtualAddress,
            exports[i].FunctionName );
        }
      }
      free( exports );
      exports = NULL;
    }
  } else if ( strcmp( argv[1], "-import" ) == 0 ) {
    //dump导入表
    if( !EnumImportModuleAndFunction((const char*)view.data,
                                     view.size,
                                     ImportModuleCallback,
                                     NULL,
                                     ImportFunctionRoutine,
                                     NULL ) ) {
        printf( "get import information failed\n" );
    }
  } else if ( strcmp( argv[1], "-entry" ) == 0 ) {
    //dump入口点
    IMAGE_NT_HEADERS* nt = GET_NT_HEADER( view.data );
    DWORD rva = nt->OptionalHeader.AddressOfEntryPoint;
    //计算入口点在第几个节中
    int iSection = GetSectionIndexByRva((const char*)view.data, rva );

    printf( "[ENTRY RVA]=%08X,[ENTRY SECTION]=%d\n", rva );

  //} else if( strcmp( argv[1], "-disasm" ) == 0 ) {
  //  DWORD rva = strtoul( argv[3], NULL, 16 );
  //  IMAGE_NT_HEADERS* nt = GET_NT_HEADER( view.lpData );
  //  DWORD va = rva + nt->OptionalHeader.ImageBase;
  //  DWORD raw = GetFileOffSet( view.lpData, va, view.SizeOfFile );
  //  int raw_len = 512;
  //  while( raw_len > 0 ) {
  //    t_disasm da = {0};
  //    //获取反汇编指令长度
  //    int len = Disasm( (unsigned char*)view.lpData + raw,
  //                      raw_len, va, &da, 4 );
  //    if( len <= 0 )
  //      break;
  //    raw += len;
  //    raw_len -= len;
  //    va += len;
  //    printf( "[DISASM]%s==%s\n", da.dump, da.result );
  //  }
  } else if( strcmp( argv[1], "-gap") == 0 ) {
    //dump节缝隙
    DWORD size = 0;
    SECTION_GAP gaps[256] = {0};
    size = EnumSectionGap( (const char*)view.data,
                           view.size,
                           gaps,
                           sizeof( gaps ) );
    DWORD i =0;
    for( ; i < size / sizeof( SECTION_GAP ); i++ ) {
      printf( "Gap  Offset:0x%08X Size:0x%08X\n",
              gaps[i].offset, gaps[i].length );
    }
  } else if( strcmp( argv[1], "-resource") == 0 ) {
    vector<RESITEM> ctItem;
    if( !WalkRes( &view, &ctItem ) ) {
      printf( "Walk Resource Failed" );
    } else {
      std::vector<RESITEM>::iterator it = ctItem.begin();
      for( ; it != ctItem.end(); it++ ) {
        printf( "Name: %s", it->name.c_str() );
        printf( "\tOffset:0x%08x\tSize:0x%08X\n",
          it->offset, it->size );
      }

    }
  } else if( strcmp( argv[1], "-icon") == 0 ) {
    char *ico_file = argv[3];
    if( !GetIcon((const char*)view.data, view.size, ico_file)) {
      printf("GetIcon failed");
    } else {
      printf("GetIcon successed");
    }
  } else if( strcmp( argv[1], "-loadimage") == 0 ) {
    char *dump_file = argv[3];
    IMAGE_NT_HEADERS *nt = GET_NT_HEADER(view.data);

    char *image = (char*)VirtualAlloc(0,
                                      nt->OptionalHeader.SizeOfImage,
                                      MEM_COMMIT,
                                      PAGE_EXECUTE_READWRITE);
    if (image==NULL) {
      printf("allocate image failed\n");
    } else {
      memset(image, 0, nt->OptionalHeader.SizeOfImage);
      printf("image address 0x%08X\n", image);
      if (!LoadPEImage((const char*)view.data, view.size, image, nt->OptionalHeader.SizeOfImage)) {
        printf("load image failed\n");
      } else {
        FILE *fp = fopen(dump_file, "wb");
        fwrite(image, nt->OptionalHeader.SizeOfImage, 1, fp);
        fclose(fp);
        VirtualFree(image, nt->OptionalHeader.SizeOfImage, MEM_DECOMMIT);
        printf("load image success\n");
      }
    }
  } else if( strcmp( argv[1], "-version") == 0 ) {
    //dump版本信息
    PE_VERSION verinfo;
    memset( &verinfo, 0, sizeof( verinfo ) );
    if ( GetVersionInfo( argv[2], &verinfo ) ) {
      //获取版本信息失败
      if( strlen( verinfo.FileVersion ) > 0 ) {
        printf( "FileVersion==%s", verinfo.FileVersion );
      }

      if( strlen( verinfo.CompanyName ) > 0 ) {
        printf( "CompanyName==%s", verinfo.CompanyName );
      }

      if( strlen( verinfo.FileDescription ) > 0 ) {
        printf( "FileDescription==%s", verinfo.FileDescription );
      }

      if( strlen( verinfo.ProductName ) > 0 ) {
        printf( "ProductName==%s", verinfo.ProductName );
      }

      if( strlen( verinfo.LegalCopyright ) > 0 ) {
        printf( "LegalCopyright==%s", verinfo.LegalCopyright );
      }

      if( strlen( verinfo.InternalName ) > 0 ) {
        printf( "InternalName==%s", verinfo.InternalName );
      }

      if( strlen( verinfo.Comments ) > 0 ) {
        printf( "Comments==%s", verinfo.Comments );
      }

      if( strlen( verinfo.SpecialBuild ) > 0 ) {
        printf( "SpecialBuild==%s", verinfo.SpecialBuild );
      }

      if( strlen( verinfo.LegalTrademarks ) > 0 ) {
        printf( "LegalTrademarks==%s", verinfo.LegalTrademarks );
      }

      if( strlen( verinfo.PrivateBuild ) > 0 ) {
        printf( "PrivateBuild==%s", verinfo.PrivateBuild );
      }

      if( strlen( verinfo.ProductVersion ) > 0 ) {
        printf( "ProductVersion==%s", verinfo.ProductVersion );
      }

      if( strlen( verinfo.OriginalFilename ) > 0 ) {
        printf( "OriginalFilename==%s", verinfo.OriginalFilename );
      }
    }
  } else {
    show_usage();
  }

  unmap_file( &view );

  return 0;
}





