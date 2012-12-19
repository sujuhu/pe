#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif
//#include <stdio.h>
//#include <stdlib.h>
//#include <string>
#include <Python.h>
#include <structmember.h>
#include "util/filemap.h"
#include "util/memhelp.h"
#include "petype.h"
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

extern "C"
PyObject* pype_open(PyObject* self, PyObject* args)
{
  const char* filename = NULL;  
  if(!PyArg_ParseTuple(args, "s", &filename)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  int fd = pe_open_file(filename);
  if (fd == INVALID_PE) {
    PyErr_SetString(PyExc_TypeError, "invalid pe file");
    return NULL;
  }

  return Py_BuildValue("I", fd);
}

extern "C"
PyObject* pype_close(PyObject* self, PyObject* args)
{
  int fd = INVALID_PE;  
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  pe_close(fd);
  Py_RETURN_NONE;
}


//dump节表
extern "C"
PyObject* pype_sections(PyObject* self, PyObject* args)
{
  int fd = INVALID_PE;  
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  PyObject* pTuple = NULL;
  IMAGE_NT_HEADERS32*nt = pe_nt_header(fd);
  //Py_RETURN_NONE;
  pTuple = PyTuple_New( nt->FileHeader.NumberOfSections );
  assert(PyTuple_Size(pTuple) == nt->FileHeader.NumberOfSections );
  for( int i = 0; i < nt->FileHeader.NumberOfSections; i++ ) {
    IMAGE_SECTION_HEADER* header = pe_section_header(fd, i);
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


//枚举导入函数回调函数
extern "C"
PyObject* pype_imports(PyObject* self, PyObject* args)
{
  int fd = INVALID_PE;  
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  PyObject* pList = PyList_New( 0 );

  IMAGE_IMPORT_DESCRIPTOR* dll = pe_import_dll_first(fd);
  for (; dll != NULL; dll = pe_import_dll_next(dll)) {
    char dllname[256] = {0};
    if (!pe_import_dllname(fd, dll, dllname, sizeof(dllname) - 1)) {
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
PyObject* pype_exports(PyObject* self, PyObject* args)
{
  int fd = INVALID_PE;  
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  PyObject* pDict = PyDict_New();
  const char* dllname = pe_export_dllname(fd);
  if (dllname != NULL) {
    PyDict_SetItem(pDict,  Py_BuildValue("s", "dllname"), 
      Py_BuildValue("s", dllname));  
  }
  
  IMAGE_EXPORT_FUNCTION* api = pe_export_first(fd);
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
PyObject* pype_overlay(PyObject* self, PyObject* args )
{
  int fd = INVALID_PE;  
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  IMAGE_OVERLAY* overlay = pe_overlay(fd);
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
PyObject* pype_entrypoint(PyObject* self, PyObject* args )
{
  int fd = INVALID_PE;  
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  //dump入口点
  IMAGE_NT_HEADERS32* nt = pe_nt_header(fd);
  if (nt == NULL) {
    PyErr_SetString(PyExc_ValueError, "can not found nt_header in pe");
    return NULL;    
  }
  uint32_t rva = nt->OptionalHeader.AddressOfEntryPoint;
  //计算入口点在第几个节中
  int iSection = pe_section_by_rva(fd, rva );

  PyObject* pTuple = PyTuple_New( 2 );
  PyTuple_SetItem( pTuple, 0, Py_BuildValue( "I", rva ) );
  PyTuple_SetItem( pTuple, 1, Py_BuildValue( "I", iSection ) );
  return pTuple;
}

extern "C"
PyObject* pype_icon(PyObject* self, PyObject* args )
{
  if (!args || PyObject_Length(args) != 2) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 2 expected:(int fd, char* ico_file)" );
    return NULL;
  }

  int fd = INVALID_PE;  
  char* ico_file = NULL;
  if(!PyArg_ParseTuple(args, "Is", &fd, &ico_file)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  if (!pe_icon_file(fd, ico_file)){
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
      if (parent == NULL && pe_restype_name(res->Id) != NULL) {
        snprintf(name, sizeof(name)-1, pe_restype_name(res->Id));
      } else {
        snprintf(name,sizeof(name)-1, "%d", res->Id);  
      }
    }

    if (IS_RESOURCE_DIRECTORY(res)) {
      PyObject* sublist = PyList_New(0);
      WalkResource(pe, res, sublist);
      PyObject* PyDict = PyDict_New();
      PyDict_SetItem(PyDict, Py_BuildValue("s", "name"), 
          Py_BuildValue("s", name));
      PyDict_SetItem(PyDict, Py_BuildValue("s", "sub"), sublist);
      PyList_Append( PyList, PyDict );
    } else{
      IMAGE_RESOURCE_DATA_ENTRY* data = pe_resource_data(pe, res);
      if (data == NULL) {
        continue;
      }

      PyObject* PyDict = PyDict_New();
      PyDict_SetItem(PyDict, Py_BuildValue("s", "name"), 
          Py_BuildValue("s", name));
      PyDict_SetItem(PyDict, Py_BuildValue("s", "offset"),
          Py_BuildValue( "l", data->OffsetToData ) );
      PyDict_SetItem( PyDict, Py_BuildValue( "s", "size"),
          Py_BuildValue( "l", data->Size ) );
      PyList_Append( PyList, PyDict );
    }
  }
}

extern "C"
PyObject* pype_resource(PyObject* self, PyObject* args )
{
  int fd = INVALID_PE;  
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  PyObject* PyList = PyList_New(0);
  WalkResource(fd, NULL, PyList);
  return PyList;
}

extern "C"
PyObject* pype_verinfo(PyObject* self, PyObject* args )
{
  int fd = INVALID_PE;
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  //dump版本信息
  PyObject* pDict = PyDict_New();
  IMAGE_VERSION* version = pe_version_first(fd);
  if (version == NULL) {
    Py_RETURN_NONE;
  }

  for (; version != NULL; version = pe_version_next(version)) {
    PyDict_SetItem(pDict, 
      Py_BuildValue("s", version->name), 
      Py_BuildValue("s", version->value));
  }

  return pDict;
}

extern "C"
PyObject* pype_nt_header(PyObject* self, PyObject* args)
{
  int fd = INVALID_PE;
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  return Py_BuildValue("z", pe_nt_header(fd));
}

extern "C"
PyObject* pype_dos_header(PyObject* self, PyObject* args)
{
  int fd = INVALID_PE;
  IMAGE_DOS_HEADER* dos = NULL;
  if(!PyArg_ParseTuple(args, "Iz", &fd, &dos)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  memcpy(dos, (char*)pe_dos_header(fd), sizeof(IMAGE_DOS_HEADER));
  Py_RETURN_TRUE;
  //return Py_BuildValue("z", );
}

extern "C"
PyObject* pype_gaps(PyObject* self, PyObject* args)
{
  int fd = INVALID_PE;
  if(!PyArg_ParseTuple(args, "I", &fd)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  }

  IMAGE_GAP* gap = pe_gap_first(fd);
  PyObject* pList = PyList_New(0);
  for (; gap != NULL; gap = pe_gap_next(gap)) {
    uint8_t* data = pe_data_by_raw(fd, gap->offset);
    if (data = NULL) {
      continue;
    }


    PyObject* item = PyDict_New();
    PyDict_SetItem( item,
      Py_BuildValue( "s", "offset" ),
      Py_BuildValue( "I", gap->offset));
    PyDict_SetItem( item,
      Py_BuildValue( "s", "size" ),
      Py_BuildValue( "I", gap->size ));
    PyDict_SetItem(item,
      Py_BuildValue( "s", "zero" ),
      Py_BuildValue( "I", is_zero_memory((const char*)data, gap->size)));
    PyList_Append( pList, item );
  }

  return pList;
}

static PyMethodDef peMethods[] =
{
  {"open",    pype_open, METH_VARARGS,     "open(fd, filename)"},  
  {"close",    pype_close, METH_VARARGS,     "close(fd)"},
  {"dos_header", pype_dos_header, METH_VARARGS, "dos_header(fd)"},
  {"nt_header", pype_nt_header, METH_VARARGS, ""},
  {"sections", pype_sections, METH_VARARGS,  ""},  
  {"imports",  pype_imports, METH_VARARGS,    ""},  
  {"exports", pype_exports, METH_VARARGS, ""},  
  {"overlay",  pype_overlay, METH_VARARGS,   ""},  
  {"verinfo",  pype_verinfo, METH_VARARGS,   ""},  
  {"entrypoint",  pype_entrypoint, METH_VARARGS,   ""},  
  {"resource",  pype_resource, METH_VARARGS,   ""},  
  {"icon",  pype_icon, METH_VARARGS,   ""},  
  {"gaps", pype_gaps, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initpype()
{
  Py_InitModule("pype", peMethods);
}