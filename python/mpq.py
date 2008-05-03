"""wrapper for libmpq"""

import ctypes

libmpq = ctypes.CDLL("libmpq.so")

class Error(Exception): pass

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
    -10: (IndexError, "file not in archive"),
    -11: (AssertionError, "decrypt"),
    -12: (AssertionError, "unpack"),
}

def check_error(result, func, arguments, libmpq=libmpq, errors=errors):
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

libmpq.libmpq__block_open_offset.errcheck = check_error
libmpq.libmpq__block_close_offset.errcheck = check_error
libmpq.libmpq__block_packed_size.errcheck = check_error
libmpq.libmpq__block_unpacked_size.errcheck = check_error
libmpq.libmpq__block_offset.errcheck = check_error
libmpq.libmpq__block_seed.errcheck = check_error
libmpq.libmpq__block_read.errcheck = check_error

__version__ = libmpq.libmpq__version()

libmpq.libmpq__init()

class Reader:
    def __init__(self, file, libmpq=libmpq):
        self._file = file
        self._pos = 0
        self._buf = ""
        self._cur_block = 0
        libmpq.libmpq__block_open_offset(self._file._archive._mpq, self._file.number)
    def tell(self):
        return self._pos
    def read(self, length=-1, libmpq=libmpq, ctypes=ctypes):
        if length < 0:
            length = self._file.unpacked_size
        while True:
            bsize = ctypes.c_int()
            try:
                libmpq.libmpq__block_unpacked_size(self._file._archive._mpq, self._file.number, self._cur_block, ctypes.byref(bsize))
            except IndexError:
                pass
            else:
                buf = ctypes.create_string_buffer(bsize.value)
                libmpq.libmpq__block_read(self._file._archive._mpq, self._file.number, self._cur_block, buf, ctypes.c_longlong(len(buf)), None)
                self._buf = self._buf + buf.raw
                self._cur_block += 1
                if len(self._buf) < length: continue
            ret = self._buf[:length]
            self._buf = self._buf[length:]
            self._pos += length
            return ret


class File:
    def __init__(self, archive, number, libmpq=libmpq, ctypes=ctypes):
        self._archive = archive
        self.number = number
        
        for name, type in [
                    ("packed_size", ctypes.c_longlong),
                    ("unpacked_size", ctypes.c_longlong),
                    ("offset", ctypes.c_longlong),
                    ("blocks", ctypes.c_int),
                    ("encrypted", ctypes.c_int),
                    ("compressed", ctypes.c_int),
                    ("imploded", ctypes.c_int),
                ]:
            data = type()
            func = getattr(libmpq, "libmpq__file_"+name)
            func(self._archive._mpq, self.number, ctypes.byref(data))
            setattr(self, name, data.value)
        
        buf = ctypes.create_string_buffer(1024)
        libmpq.libmpq__file_name(self._archive._mpq, self.number, buf, len(buf))
        self.name = buf.value
    
    def __str__(self, libmpq=libmpq, ctypes=ctypes):
        data = ctypes.create_string_buffer(self.unpacked_size)
        libmpq.libmpq__file_read(self._archive._mpq, data, ctypes.c_longlong(len(data)), self.number, None)
        return data.raw
    
    def __iter__(self, Reader=Reader):
        return Reader(self)

class Archive:
    def __init__(self, filename, libmpq=libmpq, File=File, ctypes=ctypes):
        if isinstance(filename, File):
          assert not filename.encrypted and not filename.compressed and not filename.imploded
          self.filename = filename._archive.filename
          offset = filename._archive.offset + filename.offset
        else:
          self.filename = filename
          offset = -1
        
        self._mpq = ctypes.c_void_p()
        libmpq.libmpq__archive_open(ctypes.byref(self._mpq), self.filename, ctypes.c_longlong(offset))
        self._opened = True
        
        for name, type in [
                    ("packed_size", ctypes.c_longlong),
                    ("unpacked_size", ctypes.c_longlong),
                    ("offset", ctypes.c_longlong),
                    ("version", ctypes.c_int),
                    ("files", ctypes.c_int),
                ]:
            data = type()
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
del Reader, File, libmpq, ctypes, errors # unclean
