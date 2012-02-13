import os
import pype

#test_file = r'../examples/0c94b325dca948dcdf81036a5306901b.sample'
test_file = r'../examples/87f6447ba9b75486969b59e1c911ac72.sample'
#test_file = r'../examples/test.bin'

fd = file(test_file, 'rb')
data = fd.read()
fd.close()

data_size = os.path.getsize(test_file)

sections = pype.sections( data, data_size )
for section in sections:
    print "%-8s\t%08X\t%08X\t%08X\t%08X\t%08X" % ( section['name'],
                                             section['vaddr'],
                                             section['vsize'],
                                             section['raw'],
                                             section['rawsize'],
                                             section['characteristics'] )

imports = pype.imports( data, data_size )
if imports is not None:
    for item in imports:
        print "%-32s%s" % ( item['module'], item['function'] )

exports = pype.exports( data, data_size )
if exports is not None:
    print "DllName: %s" % exports['dllname']
    for symbol in exports['symbols']:
        print "%s" % symbol['name']

overlay = pype.overlay( data, data_size )
if overlay is not None:
    print "Overlay Offset: 0x%08X, Size: 0x%08X" % (overlay['offset'], overlay['size'] )

verinfo = pype.verinfo( test_file )
if verinfo is not None:
    for item in verinfo.items():
        print "%-32s = %s" %( item[0], item[1] )

entry = pype.entrypoint( data, data_size )
print "ENTRY RVA:0x%08X, SectionIndex: %d" % entry

res = pype.resource( data, data_size )
print res
for item in res:
    print "\tName: %s, Offset:0x%08X Size:0x%08X\n" %( item['name'], item['offset'],
                                                               item['size'] )

ico_file = r"../examples/test.ico"

if not pype.icon( data,data_size, os.path.abspath(ico_file)):
    print "extract ico file fail"
else:
    print ico_file

print "test passed"
