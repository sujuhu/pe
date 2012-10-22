from distutils.core import setup, Extension
import platform 
osname = platform.system()
shared_libs = []

if osname == "Windows":
    defines = [ ('WIN32',None),
                ("_CRT_SECURE_NO_DEPRECATE",None),
                ("_CRT_NONSTDC_NO_DEPRECATE",None)]
else:
    defines = []

module1 = Extension('pype',
                    sources = ['pype.cpp', 'pe.cpp', 'util/strconv.cpp',
                        'util/filemap.cpp'],
                    include_dirs = ['./util', './struct'],
                    define_macros = defines,
                    #library_dirs=[r'c:\Program Files\Microsoft SDKs\Windows\v6.0A\Lib',
                    #              "../build"],
                    #library_dirs = ["../build"],
                    libraries = shared_libs,
                    extra_objects = [],
                    #extra_compile_args=["/MT", "/W3", "/Od", "/Oy", "/Zi"],
                    #extra_compile_args=["/Od","/Zi"],
                    #extra_link_args=["/nologo",
                    #                 "/debug",
                    #                 "/incremental:no",
                    #                 "/opt:ref",
                    #                ]
)
setup ( name = 'pype',
        version = '0.4',
        description = 'Python module wrapping libpe',
        ext_modules = [module1])
