#coding = utf-8
import os,sys
import struct
import pype
import string
from ctypes import *



        
# Section characteristics.

#      IMAGE_SCN_TYPE_REG                   0x00000000  # Reserved.
#      IMAGE_SCN_TYPE_DSECT                 0x00000001  # Reserved.
#      IMAGE_SCN_TYPE_NOLOAD                0x00000002  # Reserved.
#      IMAGE_SCN_TYPE_GROUP                 0x00000004  # Reserved.
IMAGE_SCN_TYPE_NO_PAD               = 0x00000008  # Reserved.
#      IMAGE_SCN_TYPE_COPY                  0x00000010  # Reserved.

IMAGE_SCN_CNT_CODE                  = 0x00000020  # Section contains code.
IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040  # Section contains initialized data.
IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080  # Section contains uninitialized data.

IMAGE_SCN_LNK_OTHER                 = 0x00000100  # Reserved.
IMAGE_SCN_LNK_INFO                  = 0x00000200  # Section contains comments or some other type of information.
#      IMAGE_SCN_TYPE_OVER                  0x00000400  # Reserved.
IMAGE_SCN_LNK_REMOVE                = 0x00000800  # Section contents will not become part of image.
IMAGE_SCN_LNK_COMDAT                = 0x00001000  # Section contents comdat.
#                                           0x00002000  # Reserved.
#      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
IMAGE_SCN_NO_DEFER_SPEC_EXC         = 0x00004000  # Reset speculative exceptions handling bits in the TLB entries for this section.
IMAGE_SCN_GPREL                     = 0x00008000  # Section content can be accessed relative to GP
IMAGE_SCN_MEM_FARDATA               = 0x00008000
#      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
IMAGE_SCN_MEM_PURGEABLE             = 0x00020000
IMAGE_SCN_MEM_16BIT                 = 0x00020000
IMAGE_SCN_MEM_LOCKED                = 0x00040000
IMAGE_SCN_MEM_PRELOAD               = 0x00080000

IMAGE_SCN_ALIGN_1BYTES              = 0x00100000  #
IMAGE_SCN_ALIGN_2BYTES              = 0x00200000  #
IMAGE_SCN_ALIGN_4BYTES              = 0x00300000  #
IMAGE_SCN_ALIGN_8BYTES              = 0x00400000  #
IMAGE_SCN_ALIGN_16BYTES             = 0x00500000  # Default alignment if no others are specified.
IMAGE_SCN_ALIGN_32BYTES             = 0x00600000  #
IMAGE_SCN_ALIGN_64BYTES             = 0x00700000  #
IMAGE_SCN_ALIGN_128BYTES            = 0x00800000  #
IMAGE_SCN_ALIGN_256BYTES            = 0x00900000  #
IMAGE_SCN_ALIGN_512BYTES            = 0x00A00000  #
IMAGE_SCN_ALIGN_1024BYTES           = 0x00B00000  #
IMAGE_SCN_ALIGN_2048BYTES           = 0x00C00000  #
IMAGE_SCN_ALIGN_4096BYTES           = 0x00D00000  #
IMAGE_SCN_ALIGN_8192BYTES           = 0x00E00000  #
# Unused                                    0x00F00000
IMAGE_SCN_ALIGN_MASK                = 0x00F00000

IMAGE_SCN_LNK_NRELOC_OVFL           = 0x01000000  # Section contains extended relocations.
IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000  # Section can be discarded.
IMAGE_SCN_MEM_NOT_CACHED            = 0x04000000  # Section is not cachable.
IMAGE_SCN_MEM_NOT_PAGED             = 0x08000000  # Section is not pageable.
IMAGE_SCN_MEM_SHARED                = 0x10000000  # Section is shareable.
IMAGE_SCN_MEM_EXECUTE               = 0x20000000  # Section is executable.
IMAGE_SCN_MEM_READ                  = 0x40000000  # Section is readable.
IMAGE_SCN_MEM_WRITE                 = 0x80000000  # Section is writeable.



STRUCT_SIZEOF_TYPES = {
    'x': 1, 'c': 1, 'b': 1, 'B': 1,
    'h': 2, 'H': 2,
    'i': 4, 'I': 4, 'l': 4, 'L': 4, 'f': 4,
    'q': 8, 'Q': 8, 'd': 8,
    's': 1 }


class PEFormatError(Exception):
    """Generic PE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class Structure:
    """Prepare structure object to extract members from data.

    Format is a list containing definitions for the elements
    of the structure.
    """


    def __init__(self, format, name=None, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
        #self.values = {}
        self.__format_length__ = 0
        self.__field_offsets__ = dict()
        self.__set_format__(format[1])
        self.__all_zeroes__ = False
        self.__unpacked_data_elms__ = None
        self.__file_offset__ = file_offset
        if name:
            self.name = name
        else:
            self.name = format[0]


    def __get_format__(self):
        return self.__format__

    def get_field_absolute_offset(self, field_name):
        """Return the offset within the field for the requested field in the structure."""
        return self.__file_offset__ + self.__field_offsets__[field_name]

    def get_field_relative_offset(self, field_name):
        """Return the offset within the structure for the requested field."""
        return self.__field_offsets__[field_name]

    def get_file_offset(self):
        return self.__file_offset__

    def set_file_offset(self, offset):
        self.__file_offset__ = offset

    def all_zeroes(self):
        """Returns true is the unpacked data is all zeros."""

        return self.__all_zeroes__

    def sizeof_type(self, t):
        count = 1
        _t = t
        if t[0] in string.digits:
            # extract the count
            count = int( ''.join([d for d in t if d in string.digits]) )
            _t = ''.join([d for d in t if d not in string.digits])
        return STRUCT_SIZEOF_TYPES[_t] * count

    def __set_format__(self, format):

        offset = 0
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type

                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [x[:len(elm_name)] for x in self.__keys__]
                        occ_count = search_list.count(elm_name)
                        elm_name = elm_name+'_'+str(occ_count)
                    names.append(elm_name)
                    self.__field_offsets__[elm_name] = offset

                offset += self.sizeof_type(elm_type)

                # Some PE header structures have unions on them, so a certain
                # value might have different names, so each key has a list of
                # all the possible members referring to the data.
                self.__keys__.append(names)

        self.__format_length__ = struct.calcsize(self.__format__)


    def sizeof(self):
        """Return size of the structure."""

        return self.__format_length__


    def __unpack__(self, data):

        if len(data) > self.__format_length__:
            data = data[:self.__format_length__]

        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        elif len(data) < self.__format_length__:
            raise PEFormatError('Data length less than expected header length.')


        if data.count(chr(0)) == len(data):
            self.__all_zeroes__ = True

        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in xrange(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
                #self.values[key] = self.__unpacked_data_elms__[i]
                setattr(self, key, self.__unpacked_data_elms__[i])


    def __pack__(self):

        new_values = []

        for i in xrange(len(self.__unpacked_data_elms__)):

            for key in self.__keys__[i]:
                new_val = getattr(self, key)
                old_val = self.__unpacked_data_elms__[i]

                # In the case of Unions, when the first changed value
                # is picked the loop is exited
                if new_val != old_val:
                    break

            new_values.append(new_val)

        return struct.pack(self.__format__, *new_values)


    def __str__(self):
        return '\n'.join( self.dump() )

    def __repr__(self):
        return '<Structure: %s>' % (' '.join( [' '.join(s.split()) for s in self.dump()] ))


    def dump(self, indentation=0):
        """Returns a string representation of the structure."""

        dump = []

        dump.append('[%s]' % self.name)

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, int) or isinstance(val, long):
                    val_str = '0x%-8X' % (val)
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s UTC]' % time.asctime(time.gmtime(val))
                        except exceptions.ValueError, e:
                            val_str += ' [INVALID TIME]'
                else:
                    val_str = ''.join(filter(lambda c:c != '\0', str(val)))

                dump.append('0x%-8X 0x%-3X %-30s %s' % (
                    self.__field_offsets__[key] + self.__file_offset__,
                    self.__field_offsets__[key], key+':', val_str))

        return dump



class PE():

    #
    # Format specifications for PE structures.
    #

    __IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER',
        ('H,e_magic', 'H,e_cblp', 'H,e_cp',
        'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc',
        'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum',
        'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res',
        'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
        'I,e_lfanew'))

    __IMAGE_FILE_HEADER_format__ = ('IMAGE_FILE_HEADER',
        ('H,Machine', 'H,NumberOfSections',
        'I,TimeDateStamp', 'I,PointerToSymbolTable',
        'I,NumberOfSymbols', 'H,SizeOfOptionalHeader',
        'H,Characteristics'))

    __IMAGE_DATA_DIRECTORY_format__ = ('IMAGE_DATA_DIRECTORY',
        ('I,VirtualAddress', 'I,Size'))


    __IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER',
        ('H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'I,SizeOfCode',
        'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
        'I,AddressOfEntryPoint', 'I,BaseOfCode', 'I,BaseOfData',
        'I,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
        'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
        'H,MajorImageVersion', 'H,MinorImageVersion',
        'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
        'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
        'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
        'I,SizeOfStackReserve', 'I,SizeOfStackCommit',
        'I,SizeOfHeapReserve', 'I,SizeOfHeapCommit',
        'I,LoaderFlags', 'I,NumberOfRvaAndSizes' ))


    __IMAGE_OPTIONAL_HEADER64_format__ = ('IMAGE_OPTIONAL_HEADER64',
        ('H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'I,SizeOfCode',
        'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
        'I,AddressOfEntryPoint', 'I,BaseOfCode',
        'Q,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
        'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
        'H,MajorImageVersion', 'H,MinorImageVersion',
        'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
        'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
        'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
        'Q,SizeOfStackReserve', 'Q,SizeOfStackCommit',
        'Q,SizeOfHeapReserve', 'Q,SizeOfHeapCommit',
        'I,LoaderFlags', 'I,NumberOfRvaAndSizes' ))


    __IMAGE_NT_HEADERS_format__ = ('IMAGE_NT_HEADERS', ('I,Signature',))

    def __unpack_data__(self, format, data, file_offset):
        """Apply structure format to raw data.

        Returns and unpacked structure object if successful, None otherwise.
        """

        structure = Structure(format, file_offset=file_offset)

        try:
            structure.__unpack__(data)
        except PEFormatError, err:
            print 'Corrupt header "%s" at file offset %d. Exception: %s' % (
                    format[0], file_offset, str(err)) 
            return None

        self.__structures__.append(structure)

        return structure

    def __init__(self, file):
    	self._fd = pype.open(file)
    	self.filesize = os.path.getsize(file)

    def imports(self):
    	return pype.imports(self._fd)

    def exports(self):
    	return pype.exports(self._fd)

    def sections(self):
    	return pype.sections(self._fd)

    def resource(self):
    	return pype.resource(self._fd)

    def overlay(self):
    	return pype.overlay(self._fd)

    def entrypoint(self):
    	return pype.entrypoint(self._fd)

    def icon(self, ico_file):
    	return pype.icon(self._fd, ico_file)

    def verinfo(self):
    	return pype.verinfo(self._fd)

    def gaps(self):
    	return pype.gaps(self._fd)

    def close(self):
    	pype.close(self._fd)
    	self._fd = None

if __name__ == "__main__":
	test_file = r'../../../examples/c9f225f98574759e377bce6d87958c9c.sample'
	test_file = os.path.abspath(test_file)
	if not os.path.exists(test_file):
		print "file not exist"
		sys.exit(0)
	pe = PE(test_file)
	print pe.sections()
	print pe.imports()
	print pe.exports()
	print pe.overlay()
	print pe.entrypoint()
	print pe.resource()
	print pe.gaps()