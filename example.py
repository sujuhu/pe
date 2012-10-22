import os, sys
sys.path.append("./build/python/lib.win32-2.7")
import pype

#test_file = r'../examples/0c94b325dca948dcdf81036a5306901b.sample'
#test_file = r'../examples/87f6447ba9b75486969b59e1c911ac72.sample'
#test_file = r'../examples/test.bin'
test_file = r'./examples/kernel32.dll'
test_file = os.path.abspath(test_file)

def dump_pe(filename):
    pe = pype.PE(test_file)
    
    sections = pe.sections()

    if sections is not None:
        for section in sections:
            print "%-8s\t%08X\t%08X\t%08X\t%08X\t%08X" % ( section['name'],
                                                     section['vaddr'],
                                                     section['vsize'],
                                                     section['raw'],
                                                     section['rawsize'],
                                                     section['characteristics'] )
    
    imports = pe.imports()
    if imports is not None:
        for item in imports:
            print "%-32s%s" % ( item['module'], item['function'] )
    exports = pe.exports()

    
    if exports is not None:
        print "DllName: %s" % exports['dllname']
        for symbol in exports['symbols']:
            print "%s" % symbol['name']
    overlay = pe.overlay()
    if overlay is not None:
        print "Overlay Offset: 0x%08X, Size: 0x%08X" % (overlay['offset'], overlay['size'] )
    else:
        print "no overlay"

    verinfo = pe.verinfo()
    if verinfo is not None:
        for item in verinfo.items():
            print "%-32s = %s" %( item[0], item[1] )
    else:
        print "version is none"
    entry = pe.entrypoint()
    print "ENTRY RVA:0x%08X, SectionIndex: %d" % entry

    res = pe.resource()
    for item in res:
        print "\tName: %s, Offset:0x%08X Size:0x%08X\n" %( item['name'], item['offset'],
                                                                   item['size'] )

    ico_file = r"../examples/test.ico"
    if not pe.icon(os.path.abspath(ico_file)):
        print "extract ico file fail"
    else:
        print ico_file
 
    pe.close()
    del pe

#while True:
dump_pe(test_file)
print "test passed"
