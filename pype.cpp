#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif
//#include <stdio.h>
//#include <stdlib.h>
//#include <string>
#include <Python.h>
#include <structmember.h>
#include "util/filemap.h"
#include "petype.h"
#include "pe.h"

typedef struct _PE 
{  
    PyObject_HEAD      // == PyObject ob_base;  定义一个PyObject对象.  
    int m_fd;  
    MAPPED_FILE m_view;
}PE; 

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

static PyObject *PE_new(PyTypeObject *type, PyObject *args, PyObject *kw) {
    PE *self = (PE*)type->tp_alloc(type, 0);
    return (PyObject *)self;
}

static int PE_init(PE *self, PyObject *args, PyObject *kwds)    //构造方法.  
{  
  const char* filename = NULL;  
  if(!PyArg_ParseTuple(args, "s", &filename)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return -1;  
  } 

  if (0 != map_file(filename, &self->m_view)) {
    PyErr_SetString(PyExc_IOError, "open file failed");
    return -1;
  }

  self->m_fd = pe_open((const char*)self->m_view.data, self->m_view.size);
  if (self->m_fd == INVALID_PE) {
    PyErr_SetString(PyExc_TypeError, "invalid pe format");
    return -1;
  }

  return 0;
} 

static void PE_destruct(PE* self)                   //析构方法.  
{  
  if (self->m_fd != INVALID_PE) {
    pe_close(self->m_fd);
    self->m_fd = INVALID_PE;  
  }

  if (self->m_view.data != NULL) {
    unmap_file(&self->m_view);
    self->m_view.data = NULL;
  }
  
  //如果还有PyObject*成员的话，要一并释放之.  
  //如：Py_XDECREF(self->Member);  
  self->ob_type->tp_free(self);
  //Py_TYPE(self)->tp_free((PyObject*)self);      //释放对象/实例.  
}  
    /*
static PyObject* PE_Str(PE* self)             //调用str/print时自动调用此函数.  
{  

       ostringstream OStr;  
       OStr<<"Name    : "<<Self->m_szName<<endl  
           <<"Math    : "<<Self->m_dMath<<endl  
           <<"English : "<<Self->m_dEnglish<<endl  
       string Str = OStr.str();  
       return Py_BuildValue("s", Str.c_str());  

  Py_RETURN_NONE;
}  
   */ 
/*
static PyObject* PE_Repr(PE* self)            //调用repr内置函数时自动调用.  
{  
  return PE_Str(self);  
} 
*/ 

//dump节表
extern "C"
PyObject* PE_sections(PE* self, PyObject* args)
{
  int fd = self->m_fd;

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

extern "C"
PyObject* PE_open(PE* self, PyObject* args)
{
  const char* filename = NULL;  
  if(!PyArg_ParseTuple(args, "s", &filename)) {  
      PyErr_SetString(PyExc_TypeError, 
        "Parse the argument FAILED! You should pass correct values!");  
      return NULL;  
  } 

  if (0 == map_file(filename, &self->m_view)) {
    PyErr_SetString(PyExc_TypeError, "open file failed");
    return NULL;
  }

  self->m_fd = pe_open((const char*)self->m_view.data, self->m_view.size);
  if (self->m_fd == INVALID_PE) {
    PyErr_SetString(PyExc_TypeError, "invalid pe format");
    return NULL;
  }

  Py_RETURN_NONE;
}

extern "C"
PyObject* PE_filesize(PE* self, PyObject* args)
{
  return Py_BuildValue("I", self->m_view.size);
}

extern "C"
PyObject* PE_close(PE* self, PyObject* args)
{
  if (self->m_fd != INVALID_PE) {
    pe_close(self->m_fd);
    self->m_fd = INVALID_PE;  
  }

  if (self->m_view.data != NULL) {
    unmap_file(&self->m_view);
    self->m_view.data = NULL;
  }
  Py_RETURN_NONE;
}

//枚举导入函数回调函数
extern "C"
PyObject* PE_imports(PE* self, PyObject* args)
{
  int pe = self->m_fd;
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
PyObject* PE_exports(PE* self, PyObject* args)
{
  int fd = self->m_fd;

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
PyObject* PE_overlay( PE* self, PyObject* args )
{
  int fd = self->m_fd;

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
PyObject* PE_entrypoint(PE* self, PyObject* args )
{
  int fd = self->m_fd;

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
PyObject* PE_icon(PE* self, PyObject* args )
{
  if (!args || PyObject_Length(args) != 1) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 1 expected:(char* ico_file)" );
    return NULL;
  }

  PyObject *py_ico_file = PyTuple_GetItem(args, 0);
  if (!check_object(py_ico_file)){
    PyErr_SetString(PyExc_ValueError, "Can't get ico_file from arguments");
    return NULL;
  }

  int fd = self->m_fd;
  char* ico_file = PyString_AsString(py_ico_file);

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
PyObject* PE_resource(PE* self, PyObject* args )
{
  int fd = self->m_fd;

  PyObject* PyList = PyList_New(0);
  WalkResource(fd, NULL, PyList);
  return PyList;
}

extern "C"
PyObject* PE_verinfo(PE* self, PyObject* args )
{
  int fd = self->m_fd;

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

static PyMethodDef PE_methods[] =
{
  {"open",    (PyCFunction)PE_open, METH_VARARGS,     "open(filename)"},  
  {"close",    (PyCFunction)PE_close, METH_NOARGS,     "close()"},
  {"file_size", (PyCFunction)PE_filesize, METH_NOARGS,  "file_size()"},  
  {"sections", (PyCFunction)PE_sections, METH_NOARGS,  ""},  
  {"imports",    (PyCFunction)PE_imports, METH_NOARGS,    ""},  
  {"exports", (PyCFunction)PE_exports, METH_NOARGS, ""},  
  {"overlay",  (PyCFunction)PE_overlay, METH_NOARGS,   ""},  
  {"verinfo",  (PyCFunction)PE_verinfo, METH_NOARGS,   ""},  
  {"entrypoint",  (PyCFunction)PE_entrypoint, METH_NOARGS,   ""},  
  {"resource",  (PyCFunction)PE_resource, METH_NOARGS,   ""},  
  {"icon",  (PyCFunction)PE_icon, METH_VARARGS,   ""},  
  {NULL, NULL, 0, NULL}
};

static PyMemberDef PE_members[] =         //类/结构的数据成员的说明.  
{  
      //{"m_fd",   T_INT, offsetof(pe, m_fd),   0, "The Name of instance"},  
      //{"m_dMath",    T_FLOAT,  offsetof(CScore, m_dMath),    0, "The Math score of instance."},  
      //{"m_dEnglish", T_FLOAT,  offsetof(CScore, m_dEnglish), 0, "The English score of instance."},  
      //{"m_dTotal",   T_FLOAT,  offsetof(CScore, m_dTotal),   0, "The Total score of instance.align"},  
  
      {NULL, NULL, NULL, 0, NULL}  
}; 

static PyTypeObject pyep_PEType =  
{  
       PyObject_HEAD_INIT(NULL)
       0,
       "pype.PE",                 //可以通过__class__获得这个字符串. CPP可以用类.__name__获取.  
       sizeof(PE),                 //类/结构的长度.调用PyObject_New时需要知道其大小.  
   0,                             /* tp_itemsize */
    (destructor)PE_destruct,   /* tp_dealloc */
    0,                             /* tp_print */
    0,                             /* tp_getattr */
    0,                             /* tp_setattr */
    0,                             /* tp_compare */
    0,                             /* tp_repr */
    0,                             /* tp_as_number */
    0,                             /* tp_as_sequence */
    0,                             /* tp_as_mapping */
    0,                             /* tp_hash */
    0,                             /* tp_call */
    0,                             /* tp_str */
    0,                             /* tp_getattro */
    0,                             /* tp_setattro */
    0,                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,            /* tp_flags */
    "My first pe object.",    /* tp_doc */
    0,                             /* tp_traverse */
    0,                             /* tp_clear */
    0,                             /* tp_richcompare */
    0,                             /* tp_weaklistoffset */
    0,                             /* tp_iter */
    0,                             /* tp_iternext */
    PE_methods,               /* tp_methods */
    PE_members,                             /* tp_members */
    0,                             /* tp_getset */
    0,                             /* tp_base */
    0,                             /* tp_dict */
    0,                             /* tp_descr_get */
    0,                             /* tp_descr_set */
    0,                             /* tp_dictoffset */
    (initproc)PE_init,        /* tp_init */
    0,                             /* tp_alloc */
    PE_new,                   /* tp_new */
    NULL,                             /* tp_free */
}; 

/*
static PyModuleDef ModuleInfo =  
{  
       PyModuleDef_HEAD_INIT,  
       "My C++ Class Module",               //模块的内置名--__name__.  
       "This Module Created By C++--extension a class to Python!",                 //模块的DocString.__doc__  
       -1,  
       NULL, NULL, NULL, NULL, NULL  
};  
*/


static PyMethodDef pype_methods[] = {
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initpype()
{
  //Py_InitModule("pype", peMethods);
    if (PyType_Ready(&pyep_PEType) < 0) {
        return;
    }
    PyObject * m = Py_InitModule3("pype", pype_methods, "My third LAME module.");
    Py_INCREF(&pyep_PEType);
    PyModule_AddObject(m, "PE", (PyObject *)&pyep_PEType);
}





