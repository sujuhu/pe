from distutils.core import setup, Extension
module1 = Extension('pype',
                    sources = ['pype.cpp'],
                    define_macros = [('WIN32',None),
                                     ("_CRT_SECURE_NO_DEPRECATE",None),
                                     ("_CRT_NONSTDC_NO_DEPRECATE",None)],
                    library_dirs=[r'c:\Program Files\Microsoft SDKs\Windows\v6.0A\Lib',"../"],
                    libraries=["libpe"],
                    extra_objects = [],
                    extra_compile_args=["/MT", "/W3", "/Od", "/Oy", "/Zi"],
                    extra_link_args=["/nologo",
                                     "/debug",
                                     "/incremental:no",
                                     "/opt:ref",
                                    ]
)
setup ( name = 'PackageName',
        version = '0.3.1',
        description = 'Python module wrapping libpe',
        ext_modules = [module1])
