"""
wrapper for libmpq
"""

import ctypes

libmpq = ctypes.CDLL("libmpq.so")

class Error(Exception): pass

def check_error(result, func, arguments):
    errors = {
        -1: (IOError, "open"),
        -2: (IOError, "close"),
        -3: (IOError, "seek"),
        -4: (IOError, "read"),
        -5: (IOError, "write"),
        -6: (MemoryError,),
        -7: (Error, "format"),
        -8: (Error, "not initialized"),
        -9: (Error, "buffer size too small"),
        -10: (Error, "file does not exist in archive"),
        -11: (Error, "decrypt"),
        -12: (Error, "decompress"),
        -13: (ValueError, "info"),
    }
    
    try:
        error = errors[result]
    except:  
        return result
    else:
        raise error[0](*error[1:])

libmpq.libmpq__init.errcheck = check_error
libmpq.libmpq__shutdown.errcheck = check_error

libmpq.libmpq__version.restype = ctypes.c_char_p

libmpq.libmpq__archive_open.errcheck = check_error
libmpq.libmpq__archive_close.errcheck = check_error
libmpq.libmpq__archive_info.errcheck = check_error

libmpq.libmpq__file_open.errcheck = check_error
libmpq.libmpq__file_close.errcheck = check_error
libmpq.libmpq__file_info.errcheck = check_error
libmpq.libmpq__file_name.errcheck = check_error
libmpq.libmpq__file_number.errcheck = check_error

libmpq.libmpq__file_read.errcheck = check_error

libmpq.libmpq__block_info.errcheck = check_error
libmpq.libmpq__block_read.errcheck = check_error

__version__ = libmpq.libmpq__version()

libmpq.libmpq__init()

class File:
    def __init__(self, archive, item, libmpq=libmpq, ctypes=ctypes):
        self._archive = archive
        
        if isinstance(item, str):
            self.name = item
            self.number = libmpq.libmpq__file_number(self._archive._mpq, item)
            
        elif isinstance(item, int):
            buf = ctypes.create_string_buffer(1024)
            libmpq.libmpq__file_name(self._archive._mpq, item, buf, len(buf))
            self.name = buf.value
            self.number = item
        else:
            raise TypeError, "incorrect index type"
        
        libmpq.libmpq__file_open(self._archive._mpq, self.number)
        self._opened = True
        
        for name, number in {
                    "packed_size": 1,
                    "unpacked_size": 2,
                    "encrypted": 3,
                    "compressed": 4,
                    "imploded": 5,
                    "copied": 6,
                    "single": 7,
                    "offset": 8,
                    "blocks": 9,
                    "blocksize": 10,
                }.items():
            setattr(self, name, libmpq.libmpq__file_info(self._archive._mpq, number, self.number))
    
    def __del__(self, libmpq=libmpq):
        if getattr(self, "_opened", False):
            libmpq.libmpq__file_close(self._archive._mpq, self.number)
    
    def __str__(self, libmpq=libmpq, ctypes=ctypes):
        data = ctypes.create_string_buffer(self.unpacked_size)
        libmpq.libmpq__file_read(self._archive._mpq, data, self.unpacked_size, self.number)
        return data.raw

class Archive:
    def __init__(self, filename, libmpq=libmpq, File=File, ctypes=ctypes):
        if isinstance(filename, File):
          assert filename.copied
          self.filename = filename._archive.filename
          offset = filename.offset
        else:
          self.filename = filename
          offset = -1
        
#        self._mpq = ctypes.c_void_p()
        self._mpq = ctypes.create_string_buffer(4128) # bad constant
        
#        libmpq.libmpq__archive_open(ctypes.byref(self._mpq), self.filename, offset)
        libmpq.libmpq__archive_open(self._mpq, self.filename, offset)
        self._opened = True
        
        for name, number in {
                    "size": 1,
                    "compressed_size": 2,
                    "uncompressed_size": 3,
                    "files": 4,
                    "hashtable_entries": 5,
                    "blocktable_entries": 6,
                    "blocksize": 7,
                    "version": 8,
                }.items():
            setattr(self, name, libmpq.libmpq__archive_info(self._mpq, number))
    
    def __del__(self, libmpq=libmpq):
        if getattr(self, "_opened", False):
            libmpq.libmpq__archive_close(self._mpq)
    
    def __getitem__(self, item, File=File):
        return File(self, item)

del check_error # clean
del File, libmpq, ctypes # unclean
