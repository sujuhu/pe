// pefile.cpp : Defines the entry point for the console application.
//
//#pragma  warning( disable:4996 )
#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <Python.h>
#include "pe.h"

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
  PyObject* pTuple = NULL;

  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *py_fd = PyTuple_GetItem(args, 0);
  if (!check_object(py_fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(py_fd);

  IMAGE_NT_HEADERS*nt = pe_nt_header(pe);
  pTuple = PyTuple_New( nt->FileHeader.NumberOfSections );
  assert(PyTuple_Size(pTuple) == nt->FileHeader.NumberOfSections );
  for( int i = 0; i < nt->FileHeader.NumberOfSections; i++ ) {
    IMAGE_SECTION_HEADER* header = pe_section_header(pe, i);
    PyObject* item = PyDict_New();
    PyDict_SetItem( item, Py_BuildValue( "s", "name"),
                Py_BuildValue( "s", header->Name ) );
    PyDict_SetItem( item, Py_BuildValue( "s", "vaddr" ),
                Py_BuildValue( "I", header->VirtualAddress ));
    PyDict_SetItem( item, Py_BuildValue( "s", "vsize" ),
                Py_BuildValue( "I", header->Misc.VirtualSize ));
    PyDict_SetItem( item, Py_BuildValue( "s", "raw" ),
                Py_BuildValue( "I", header->PointerToRawData ));
    PyDict_SetItem( item, Py_BuildValue( "s", "rawsize" ),
                Py_BuildValue( "I", header->SizeOfRawData ));
    PyDict_SetItem( item, Py_BuildValue( "s", "characteristics" ),
                Py_BuildValue( "I", header->Characteristics ));
    PyTuple_SetItem(pTuple, i, item );
  }

  return pTuple;
}

extern "C"
PyObject* Open(PyObject* self, PyObject* args)
{
  if (!args || PyObject_Length(args)!=2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(stream, size)" );
    return NULL;
  }

  PyObject *py_stream = PyTuple_GetItem(args, 0);
  if (!check_object(py_stream)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  PyObject *py_size = PyTuple_GetItem(args, 0);
  if (!check_object(py_size)){
    PyErr_SetString(PyExc_ValueError, "Can't get size from arguments");
    return NULL;
  }

  char* stream = PyString_AsString(py_stream);
  size_t size = PyLong_AsLong(py_size);

  int pe = pe_open(stream, size);
  if (pe == INVALID_PE) {
    PyErr_SetString(PyExc_TypeError, "Invalid PE");
    return NULL;
  }

  return PyLong_FromLong(pe);
}

extern "C"
PyObject* Close(PyObject* self, PyObject* args)
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *fd = PyTuple_GetItem(args, 0);
  if (!check_object(fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(fd);

  pe_close(pe);
  Py_RETURN_NONE;
}

//枚举导入函数回调函数
extern "C"
PyObject* imports(PyObject* self, PyObject* args)
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *fd = PyTuple_GetItem(args, 0);
  if (!check_object(fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(fd);

  PyObject* pList = PyList_New( 0 );

  IMAGE_IMPORT_DESCRIPTOR* dll = pe_import_dll_first(pe);
  for (; dll != NULL; dll = pe_import_dll_next(dll)) {
    

    char dllname[256] = {0};
    if (!pe_import_dllname(pe, dll, dllname, sizeof(dllname) - 1)) {
      continue;
    }

    IMAGE_IMPORT_FUNCTION* api = pe_import_api_first(dll);
    for (; api != NULL; api = pe_import_api_next(api)) {
      PyObject* pDict = PyDict_New();
      PyDict_SetItem( pDict, Py_BuildValue( "s", "module" ),
              Py_BuildValue( "s", dllname ) );

      PyDict_SetItem( pDict, Py_BuildValue( "s", "function" ),
        Py_BuildValue( "s", api->FunctionName ) );

      PyDict_SetItem( pDict, Py_BuildValue( "s", "mname_offset" ),
        Py_BuildValue( "I", dll->Name ) );

      PyDict_SetItem( pDict, Py_BuildValue( "s", "fname_offset" ),
        Py_BuildValue( "I", api->OffsetName ) );

      PyList_Append( pList, pDict );
    }
  }
  return pList;
}

extern "C"
PyObject* exports( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *py_fd = PyTuple_GetItem(args, 0);
  if (!check_object(py_fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(py_fd);

  PyObject* pDict = PyDict_New();
  const char* dllname = pe_export_dllname(pe);
  if (dllname != NULL) {
    PyDict_SetItem(pDict,  Py_BuildValue("s", "dllname"), 
      Py_BuildValue("s", dllname));  
  }
  
  IMAGE_EXPORT_FUNCTION* api = pe_export_first(pe);
  PyObject* pList = PyList_New(0);
  for (; api != NULL; api = pe_export_next(api)) {
    PyObject* item = PyDict_New();
    PyDict_SetItem( item,
      Py_BuildValue( "s", "ordinal" ),
      Py_BuildValue( "I", api->Ordinal) );
    PyDict_SetItem( item,
      Py_BuildValue( "s", "name" ),
      Py_BuildValue( "s", api->FunctionName ) );
    PyDict_SetItem( item,
      Py_BuildValue( "s", "va" ),
      Py_BuildValue( "I", api->FunctionVirtualAddress ) );
    PyList_Append( pList, item );
  }

  PyDict_SetItem( pDict, Py_BuildValue( "s", "symbols"), pList );

  return pDict;
}

extern "C"
PyObject* overlay( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *py_fd = PyTuple_GetItem(args, 0);
  if (!check_object(py_fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(py_fd);

  IMAGE_OVERLAY* overlay = pe_overlay(pe);
  if (overlay == NULL) {
    Py_RETURN_NONE; 
  }

  if (overlay->size == 0) {
    Py_RETURN_NONE;
  }

  PyObject* pDict = PyDict_New();
  PyDict_SetItem( pDict, Py_BuildValue( "s", "offset" ),
    Py_BuildValue( "I", overlay->offset_in_file ) );
  PyDict_SetItem( pDict, Py_BuildValue( "s", "size"),
    Py_BuildValue( "I", overlay->size ) );
  return pDict;
}

extern "C"
PyObject* entrypoint( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *py_fd = PyTuple_GetItem(args, 0);
  if (!check_object(py_fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(py_fd);

  //dump入口点
  IMAGE_NT_HEADERS* nt = pe_nt_header(pe);
  if (nt == NULL) {
    PyErr_SetString(PyExc_ValueError, "can not found nt_header in pe");
    return NULL;    
  }
  uint32_t rva = nt->OptionalHeader.AddressOfEntryPoint;
  //计算入口点在第几个节中
  int iSection = pe_section_by_rva(pe, rva );

  PyObject* pTuple = PyTuple_New( 2 );
  PyTuple_SetItem( pTuple, 0, Py_BuildValue( "I", rva ) );
  PyTuple_SetItem( pTuple, 1, Py_BuildValue( "I", iSection ) );
  return pTuple;
}

extern "C"
PyObject* icon( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args) != 2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(int fd, char* ico_file)" );
    return NULL;
  }

  PyObject *py_fd = PyTuple_GetItem(args, 0);
  if (!check_object(py_fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  PyObject *py_ico_file = PyTuple_GetItem(args, 1);
  if (!check_object(py_ico_file)){
    PyErr_SetString(PyExc_ValueError, "Can't get ico_file from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(py_fd);
  char* ico_file = PyString_AsString(py_ico_file);

  if (!pe_icon_file(pe, ico_file)){
    Py_RETURN_FALSE;
  } else {
    Py_RETURN_TRUE;
  }
}

void WalkResource(
    int pe, 
    IMAGE_RESOURCE_DIRECTORY_ENTRY* parent, 
    PyObject* PyList)
{
  IMAGE_RESOURCE_DIRECTORY_ENTRY* res = pe_resource_first(pe, parent);
  for (; res != NULL; res = pe_resource_next(res)) {
    char name[256] = {0};
    if (res->NameIsString) {
      pe_resource_name(pe, res, name, sizeof(name) - 1);
    } else {
      snprintf(name,sizeof(name)-1, "%d", res->Id);
    }

    if (IS_RESOURCE_DIRECTORY(res)) {
      WalkResource(pe, res, PyList);
    } else{
      IMAGE_RESOURCE_DATA_ENTRY* data = pe_resource_data(pe, res);
      if (data == NULL) {
        continue;
      }

      PyObject* PyDict = PyDict_New();
      PyDict_SetItem(PyDict, Py_BuildValue("s", "name"), Py_BuildValue("s", name));
      PyDict_SetItem(PyDict, Py_BuildValue("s", "offset"),
          Py_BuildValue( "l", data->OffsetToData ) );
      PyDict_SetItem( PyDict, Py_BuildValue( "s", "size"),
        Py_BuildValue( "l", data->Size ) );
      PyList_Append( PyList, PyDict );
    }
  }
}

extern "C"
PyObject* resource( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *py_fd = PyTuple_GetItem(args, 0);
  if (!check_object(py_fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(py_fd);

  PyObject* PyList = PyList_New(0);
  WalkResource(pe, NULL, PyList);
  return PyList;
}

extern "C"
PyObject* verinfo( PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args)!=1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(int fd)" );
    return NULL;
  }

  PyObject *py_fd = PyTuple_GetItem(args, 0);
  if (!check_object(py_fd)){
    PyErr_SetString(PyExc_ValueError, "Can't get fd from arguments");
    return NULL;
  }

  int pe = PyLong_AsLong(py_fd);

  //dump版本信息
  PyObject* pDict = PyDict_New();
  IMAGE_VERSION* version = pe_version_first(pe);
  for (; version != NULL; version = pe_version_next(version)) {
    PyDict_SetItem(pDict, Py_BuildValue("u", version->name), 
      Py_BuildValue( "u",version->value));
  }

  return pDict;
}

static PyMethodDef peMethods[] =
{
  {"Open",  Open, METH_VARARGS, "Open(stream, size)"},
  {"Close",  Close, METH_VARARGS, "Close(fd)"},
  {"sections",  sections, METH_VARARGS, "sections(fd)"},
  {"imports",   imports,  METH_VARARGS, "imports(fd)"},
  {"exports",   exports,  METH_VARARGS, "exports(fd)"},
  {"overlay",   overlay,  METH_VARARGS, "overlay(fd)"},
  {"verinfo",   verinfo,  METH_VARARGS, "verinfo(fd)"},
  {"entrypoint",  entrypoint,   METH_VARARGS, "entrypoint(fd)"},
  {"resource",  resource, METH_VARARGS, "resource(fd)"},
  {"icon", icon, METH_VARARGS, "icon(fd)" },
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initpype()
{
  Py_InitModule("pype", peMethods);
}





