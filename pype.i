%module pype
%{
#define SWIG_FILE_WITH_INIT
#include "../src/imgfmt.h"
#include "../src/pe.h"
// pefile.cpp : Defines the entry point for the console application.
//
#pragma  warning( disable:4996 )
#include <windows.h>
#include <python.h>
#include <vector>
using namespace std;

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
  return true;
}

bool WalkRes(char *data, size_t data_len, vector<RESITEM>* ctItem )
{
  if (!EnumResource(data, data_len, ResourceRoutine, (LPVOID)ctItem)) {
    return false;
  }

  return true;
}

/*
  Check whether we got a Python Object
*/
PyObject *check_object(PyObject *pObject)
{
  PyObject *pException;

  if(!pObject) {
    pException = PyErr_Occurred();
    if(pException)
      PyErr_Print();
    return NULL;
  }

  return pObject;
}

//dump节表
extern "C"
PyObject* sections(PyObject* self, PyObject* args)
{
  IMAGE_NT_HEADERS* nt = NULL;
  PyObject* pTuple = NULL;
  WORD i = 0;

  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, stream_size)" );
    return NULL;
  }

  PyObject *stream = PyTuple_GetItem(args, 0);
  if (!check_object(stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *stream_size = PyTuple_GetItem(args, 1);
  if (!check_object(stream_size)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }


  char* data = NULL;
  data = PyString_AsString(stream);
  size_t data_size = PyLong_AsLong(stream_size);

  if (!IsValidPE(data, data_size)) {
    PyErr_SetString(PyExc_ValueError, "file is not pe");
    return NULL;
  }

  nt = GET_NT_HEADER( data );
  pTuple = PyTuple_New( nt->FileHeader.NumberOfSections );
  assert(PyTuple_Size(pTuple) == nt->FileHeader.NumberOfSections );
  for( ; i < nt->FileHeader.NumberOfSections; i++ ) {

    IMAGE_SECTION_HEADER header = {0};
    if( GetSectionHeader( data, i, &header ) ) {
      PyObject* item = NULL;
      item = PyDict_New();
      PyDict_SetItem( item, Py_BuildValue( "s", "name"),
                  Py_BuildValue( "s", header.Name ) );
      PyDict_SetItem( item, Py_BuildValue( "s", "vaddr" ),
                  Py_BuildValue( "I", header.VirtualAddress ));
      PyDict_SetItem( item, Py_BuildValue( "s", "vsize" ),
                  Py_BuildValue( "I", header.Misc.VirtualSize ));
      PyDict_SetItem( item, Py_BuildValue( "s", "raw" ),
                  Py_BuildValue( "I", header.PointerToRawData ));
      PyDict_SetItem( item, Py_BuildValue( "s", "rawsize" ),
                  Py_BuildValue( "I", header.SizeOfRawData ));
      PyDict_SetItem( item, Py_BuildValue( "s", "characteristics" ),
                  Py_BuildValue( "I", header.Characteristics ));
      PyTuple_SetItem(pTuple, i, item );
    }
  }

  return pTuple;
}

//枚举导入函数回调函数
bool ImportFunctionRoutine( PIMPORT_FUNCTION pImportFunction,
               PIMPORT_MODULE pImportModule, LPVOID lpParam )
{
  PyObject* pList = (PyObject*)lpParam;

  PyObject* pDict = PyDict_New();
  PyDict_SetItem( pDict, Py_BuildValue( "s", "module" ),
          Py_BuildValue( "s", pImportModule->ModuleName ) );

  PyDict_SetItem( pDict, Py_BuildValue( "s", "function" ),
    Py_BuildValue( "s", pImportFunction->FunctionName ) );

  PyDict_SetItem( pDict, Py_BuildValue( "s", "mname_offset" ),
    Py_BuildValue( "I", pImportModule->OffsetName ) );

  PyDict_SetItem( pDict, Py_BuildValue( "s", "fname_offset" ),
    Py_BuildValue( "I", pImportFunction->OffsetName ) );

  PyList_Append( pList, pDict );

  return true;
}


extern "C"
PyObject* imports(PyObject* self, PyObject* args)
{
  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, stream_size)" );
    return NULL;
  }

  PyObject *stream = PyTuple_GetItem(args, 0);
  if (!check_object(stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *stream_len = PyTuple_GetItem(args, 1);
  if (!check_object(stream_len)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  char* data = NULL;
  size_t data_len = 0;
  data=PyString_AsString(stream);
  data_len = PyLong_AsLong(stream_len);

  if (!IsValidPE(data, data_len)) {
    PyErr_SetString(PyExc_ValueError, "file is not pe");
    return NULL;
  }

  PyObject* pList = PyList_New( 0 );
  if( !EnumImportModuleAndFunction( data, data_len,
                  NULL, NULL,
                  ImportFunctionRoutine, (LPVOID)pList ) ) {
    Py_RETURN_NONE;
  }
  return pList;
}

extern "C"
PyObject* exports( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, stream_size)" );
    return NULL;
  }

  PyObject *stream = PyTuple_GetItem(args, 0);
  if (!check_object(stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *stream_len = PyTuple_GetItem(args, 1);
  if (!check_object(stream_len)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  char* data = NULL;
  size_t data_len = 0;
  data = PyString_AsString(stream);
  data_len = PyLong_AsLong(stream_len);

  if (!IsValidPE(data, data_len)) {
    PyErr_SetString(PyExc_ValueError, "file is not pe");
    return NULL;
  }

  PyObject* pDict = NULL;
  CHAR DllName[256] = {0};
  if (GetExportDllName(data, data_len, DllName, sizeof( DllName )) ) {
    if( pDict == NULL )
      pDict = PyDict_New();
    PyDict_SetItem( pDict,  Py_BuildValue( "s", "dllname"),
                Py_BuildValue( "s", DllName ));
  }

  size_t size = 0;
  EnumExportFunction(data, data_len, NULL, &size);
  if( errno == EINVAL ) {
    if( size != 0 ) {
      EXPORT_FUNCTION* exports = (EXPORT_FUNCTION*)malloc( size );
      memset( exports, 0, size );
      if( EnumExportFunction(data, data_len, exports, &size ) ) {
        if( pDict == NULL )
          pDict = PyDict_New();
        DWORD i = 0;
        PyObject* pList = PyList_New(0);
        for( ; i < size / sizeof( EXPORT_FUNCTION ); i++ ) {
          PyObject* item = PyDict_New();
          PyDict_SetItem( item,
            Py_BuildValue( "s", "ordinal" ),
            Py_BuildValue( "I", exports[i].Ordinal) );
          PyDict_SetItem( item,
            Py_BuildValue( "s", "name" ),
            Py_BuildValue( "s", exports[i].FunctionName ) );
          PyDict_SetItem( item,
            Py_BuildValue( "s", "va" ),
            Py_BuildValue( "I", exports[i].FunctionVirtualAddress ) );
          PyList_Append( pList, item );
        }

        PyDict_SetItem( pDict, Py_BuildValue( "s", "symbols"), pList );
      }
      free( exports );
      exports = NULL;
    }
  }

  if( pDict )
    return pDict;
  else
    Py_RETURN_NONE;
}

extern "C"
PyObject* overlay( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, stream_size)" );
    return NULL;
  }

  PyObject *stream = PyTuple_GetItem(args, 0);
  if (!check_object(stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *stream_len = PyTuple_GetItem(args, 1);
  if (!check_object(stream_len)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  char* data = NULL;
  size_t data_len = 0;
  data = PyString_AsString(stream);
  data_len = PyLong_AsLong(stream_len);

  if (!IsValidPE(data, data_len)) {
    PyErr_SetString(PyExc_ValueError, "file is not pe");
    return NULL;
  }

  raw_t overlay_offset = 0;
  size_t overlay_size = 0;
  if( !GetOverlay(data, data_len,
              &overlay_offset, &overlay_size ) ) {
    Py_RETURN_NONE;
  } else {
    if( overlay_size != 0 ) {
      PyObject* pDict = PyDict_New();
      PyDict_SetItem( pDict, Py_BuildValue( "s", "offset" ),
        Py_BuildValue( "I", overlay_offset ) );
      PyDict_SetItem( pDict, Py_BuildValue( "s", "size"),
        Py_BuildValue( "I", overlay_size ) );
      return pDict;
    } else {
      Py_RETURN_NONE;
    }
  }
}

extern "C"
PyObject* entrypoint( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, stream_size)" );
    return NULL;
  }

  PyObject *stream = PyTuple_GetItem(args, 0);
  if (!check_object(stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *stream_len = PyTuple_GetItem(args, 1);
  if (!check_object(stream_len)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  char* data = NULL;
  size_t data_len = 0;
  data = PyString_AsString(stream);
  data_len = PyLong_AsLong(stream_len);

  if (!IsValidPE(data, data_len)) {
    PyErr_SetString(PyExc_ValueError, "file is not pe");
    return NULL;
  }

  //dump入口点
  IMAGE_NT_HEADERS* nt = GET_NT_HEADER( data );
  DWORD rva = nt->OptionalHeader.AddressOfEntryPoint;
  //计算入口点在第几个节中
  int iSection = GetSectionIndexByRva(data, rva );

  PyObject* pTuple = PyTuple_New( 2 );
  PyTuple_SetItem( pTuple, 0, Py_BuildValue( "I", rva ) );
  PyTuple_SetItem( pTuple, 1, Py_BuildValue( "I", iSection ) );
  return pTuple;
}

extern "C"
PyObject* icon( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=3) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, stream_size)" );
    return NULL;
  }

  PyObject *stream = PyTuple_GetItem(args, 0);
  if (!check_object(stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *stream_len = PyTuple_GetItem(args, 1);
  if (!check_object(stream_len)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *py_ico_file = PyTuple_GetItem(args, 2);
  if (!check_object(py_ico_file)){
    PyErr_SetString(PyExc_ValueError, "Can't get ico_file from arguments");
    return NULL;
  }

  char* data = NULL;
  size_t data_len = 0;
  data = PyString_AsString(stream);
  data_len = PyLong_AsLong(stream_len);
  char* ico_file = PyString_AsString(py_ico_file);

  if (!IsValidPE(data, data_len)) {
    PyErr_SetString(PyExc_ValueError, "file is not pe");
    return NULL;
  }

  raw_t icon_raw = 0;
  size_t icon_len = 0;
  if (!GetIcon(data, data_len, ico_file)) {
    //get icon fail
    Py_RETURN_FALSE;
  }

  Py_RETURN_TRUE;
}

extern "C"
PyObject* resource( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, stream_size)" );
    return NULL;
  }

  PyObject *stream = PyTuple_GetItem(args, 0);
  if (!check_object(stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *stream_len = PyTuple_GetItem(args, 1);
  if (!check_object(stream_len)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  char* data = NULL;
  size_t data_len = 0;
  data = PyString_AsString(stream);
  data_len = PyLong_AsLong(stream_len);

  if (!IsValidPE(data, data_len)) {
    PyErr_SetString(PyExc_ValueError, "file is not pe");
    return NULL;
  }

  PyObject* PyList = PyList_New(0);
  vector<RESITEM> ctItem;
  if (!WalkRes(data, data_len, &ctItem)) {
    Py_RETURN_NONE;
  }

  std::vector<RESITEM>::iterator it = ctItem.begin();
  for( ; it != ctItem.end(); it++ ) {
    PyObject* PyDict = PyDict_New();
    PyDict_SetItem( PyDict, Py_BuildValue( "s", "name" ),
        Py_BuildValue( "s", it->name.c_str() ) );
    PyDict_SetItem( PyDict, Py_BuildValue( "s", "offset"),
        Py_BuildValue( "l", it->offset ) );
    PyDict_SetItem( PyDict, Py_BuildValue( "s", "size"),
      Py_BuildValue( "l", it->size ) );
    PyList_Append( PyList, PyDict );
  }
  return PyList;
}

extern "C"
PyObject* verinfo( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(filename)" );
    return NULL;
  }

  PyObject *filename = PyTuple_GetItem(args, 0);
  if (!check_object(filename)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  char* file = NULL;
  file=PyString_AsString(filename);

  //dump版本信息
  PE_VERSION verinfo;
  memset( &verinfo, 0, sizeof( verinfo ) );
  if (!GetVersionInfo(file, &verinfo)) {
    Py_RETURN_NONE;
  }

  PyObject* pDict = PyDict_New();

  //获取版本信息失败
  if( strlen( verinfo.FileVersion ) > 0 ) {
    PyDict_SetItem( pDict,
    Py_BuildValue("s","FileVersion"),
    Py_BuildValue( "s", verinfo.FileVersion ) );
  }

  if( strlen( verinfo.CompanyName ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue("s","CompanyName"),
      Py_BuildValue( "s", verinfo.CompanyName ) );
  }

  if( strlen( verinfo.FileDescription ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue("s","FileDescription"),
      Py_BuildValue( "s", verinfo.FileDescription ) );
  }

  if( strlen( verinfo.ProductName ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue("s","ProductName"),
      Py_BuildValue( "s", verinfo.ProductName ) );
  }

  if( strlen( verinfo.LegalCopyright ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","LegalCopyright"),
      Py_BuildValue( "s", verinfo.LegalCopyright ) );
  }

  if( strlen( verinfo.InternalName ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","InternalName"),
      Py_BuildValue( "s", verinfo.InternalName ) );
  }

  if( strlen( verinfo.Comments ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","Comments"),
      Py_BuildValue( "s", verinfo.Comments ) );
  }

  if( strlen( verinfo.SpecialBuild ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","SpecialBuild"),
      Py_BuildValue( "s", verinfo.SpecialBuild ) );
  }

  if( strlen( verinfo.LegalTrademarks ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","LegalTrademarks"),
      Py_BuildValue( "s", verinfo.LegalTrademarks ) );
  }

  if( strlen( verinfo.PrivateBuild ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","PrivateBuild"),
      Py_BuildValue( "s", verinfo.PrivateBuild ) );
  }

  if( strlen( verinfo.ProductVersion ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","ProductVersion"),
      Py_BuildValue( "s", verinfo.ProductVersion ) );
  }

  if( strlen( verinfo.OriginalFilename ) > 0 ) {
    PyDict_SetItem( pDict,
      Py_BuildValue( "s","OriginalFilename"),
      Py_BuildValue( "s", verinfo.OriginalFilename ) );
  }

  return pDict;
}

/*
static PyMethodDef peMethods[] =
{
  {"sections",  sections, METH_VARARGS, "sections( file_path )"},
  {"imports",   imports,  METH_VARARGS, "imports( file_path )"},
  {"exports",   exports,  METH_VARARGS, "exports( file_path )"},
  {"overlay",   overlay,  METH_VARARGS, "overlay( file_path )"},
  {"verinfo",   verinfo,  METH_VARARGS, "verinfo( file_path )"},
  {"entrypoint",  entrypoint,   METH_VARARGS, "entrypoint( file_path )"},
  {"resource",  resource, METH_VARARGS, "resource( file_path )"},
  {"icon", icon, METH_VARARGS, "icon( file_path )" },
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initpype()
{
  Py_InitModule("_pype", peMethods);
}
*/

%}

%inline {
PyObject* sections(PyObject* self, PyObject* args);
%