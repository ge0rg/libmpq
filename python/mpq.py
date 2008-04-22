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
        -7: (Error, "file is not an mpq or is corrupted"),
        -8: (AssertionError, "not initialized"),
        -9: (AssertionError, "buffer size too small"),
        -10: (KeyError, "file not in archive"),
        -11: (AssertionError, "decrypt"),
        -12: (AssertionError, "decompress"),
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
libmpq.libmpq__archive_packed_size.errcheck = check_error
libmpq.libmpq__archive_unpacked_size.errcheck = check_error
libmpq.libmpq__archive_offset.errcheck = check_error
libmpq.libmpq__archive_version.errcheck = check_error
libmpq.libmpq__archive_files.errcheck = check_error

libmpq.libmpq__file_open.errcheck = check_error
libmpq.libmpq__file_close.errcheck = check_error
libmpq.libmpq__file_packed_size.errcheck = check_error
libmpq.libmpq__file_unpacked_size.errcheck = check_error
libmpq.libmpq__file_offset.errcheck = check_error
libmpq.libmpq__file_blocks.errcheck = check_error
libmpq.libmpq__file_encrypted.errcheck = check_error
libmpq.libmpq__file_compressed.errcheck = check_error
libmpq.libmpq__file_imploded.errcheck = check_error
libmpq.libmpq__file_name.errcheck = check_error
libmpq.libmpq__file_number.errcheck = check_error
libmpq.libmpq__file_read.errcheck = check_error

libmpq.libmpq__block_packed_size.errcheck = check_error
libmpq.libmpq__block_unpacked_size.errcheck = check_error
libmpq.libmpq__block_offset.errcheck = check_error
libmpq.libmpq__block_seed.errcheck = check_error
libmpq.libmpq__block_read.errcheck = check_error

__version__ = libmpq.libmpq__version()

libmpq.libmpq__init()

class Reader:
    def __init__(self, file):
        self._file = file
        self._pos = 0
        self._buf = ""
        self._cur_block = 1
    
    def read(self, length=-1, libmpq=libmpq, ctypes=ctypes):
        if length < 0:
            length = self._file.unpacked_size
        while True:
            bsize = ctypes.c_int()
            libmpq.libmpq__block_unpacked_size(self._file._archive._mpq, self._file.number, self._cur_block, ctypes.byref(bsize))
            buf = ctypes.create_string_buffer(bsize.value)
            libmpq.libmpq__block_read(self._file._archive._mpq, buf, bsize.value, self._file.number, self._cur_block)
            self._buf += buf
            self._cur_block += 1
            if len(self._buf) >= length:
                ret = self._buf[:length]
                self._buf = self._buf[length:]
                return ret


class File:
    def __init__(self, archive, number, libmpq=libmpq, ctypes=ctypes):
        self._archive = archive
        self.number = number
        
        libmpq.libmpq__file_open(self._archive._mpq, self.number)
        self._opened = True
        
        data = ctypes.c_int()
        for name in [
                    "packed_size",
                    "unpacked_size",
                    "offset",
                    "blocks",
                    "encrypted",
                    "compressed",
                    "imploded",
                ]:
            func = getattr(libmpq, "libmpq__file_"+name)
            func(self._archive._mpq, self.number, ctypes.byref(data))
            setattr(self, name, data.value)
        
            buf = ctypes.create_string_buffer(1024)
            libmpq.libmpq__file_name(self._archive._mpq, self.number, buf, len(buf))
            self.name = buf.value
    
    def __del__(self, libmpq=libmpq):
        if getattr(self, "_opened", False):
            libmpq.libmpq__file_close(self._archive._mpq, self.number)
    
    def __str__(self, libmpq=libmpq, ctypes=ctypes):
        data = ctypes.create_string_buffer(self.unpacked_size)
        libmpq.libmpq__file_read(self._archive._mpq, data, self.unpacked_size, self.number)
        return data.raw
    
    def __iter__(self, Reader=Reader):
        return Reader(self)

class Archive:
    def __init__(self, filename, libmpq=libmpq, File=File, ctypes=ctypes):
        if isinstance(filename, File):
          assert not filename.encrypted and not filename.compressed and not filename.imploded
          self.filename = file._archive.filename
          offset = filename.offset
        else:
          self.filename = filename
          offset = -1
        
        self._mpq = ctypes.c_void_p()
        libmpq.libmpq__archive_open(ctypes.byref(self._mpq), self.filename, offset)
        self._opened = True
        
        data = ctypes.c_int()
        for name in [
                    "packed_size",
                    "unpacked_size",
                    "offset",
                    "version",
                    "files",
                ]:
            func = getattr(libmpq, "libmpq__archive_"+name)
            func(self._mpq, ctypes.byref(data))
            setattr(self, name, data.value)
    
    def __del__(self, libmpq=libmpq):
        if getattr(self, "_opened", False):
            libmpq.libmpq__archive_close(self._mpq)
    
    def __getitem__(self, item, File=File, libmpq=libmpq, ctypes=ctypes):
        if isinstance(item, str):
            data = ctypes.c_int()
            libmpq.libmpq__file_number(self._mpq, item, ctypes.byref(data))
            item = data.value
        return File(self, item)

del check_error # clean
del Reader, File, libmpq, ctypes # unclean
