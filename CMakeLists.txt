cmake_minimum_required(VERSION 2.8)
project (libmpq)

include(${CMAKE_ROOT}/Modules/CheckIncludeFile.cmake)
include(${CMAKE_ROOT}/Modules/CheckFunctionExists.cmake)
include(${CMAKE_ROOT}/Modules/CheckCSourceRuns.cmake)

#AC_INIT(libmpq, 0.4.2, [mbroemme@plusserver.de], [libmpq])
set(PACKAGE_NAME "libmpq")
set(PACKAGE_VERSION "0.4.2")
set(PACKAGE_BUGREPORT "mbroemme@plusserver.de")
set(PACKAGE_TARNAME "libmpq")
set(PACKAGE_URL "https://libmpq.org/")

set(PACKAGE ${PACKAGE_NAME})
set(VERSION ${PACKAGE_VERSION})
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")


# Check for required headers
CHECK_INCLUDE_FILE(dlfcn.h HAVE_DLFCN_H)
CHECK_INCLUDE_FILE(inttypes.h HAVE_INTTYPES_H)
CHECK_INCLUDE_FILE(memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILE(stdint.h HAVE_STDINT_H)
CHECK_INCLUDE_FILE(stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILE(strings.h HAVE_STRINGS_H)
CHECK_INCLUDE_FILE(string.h HAVE_STRING_H)
CHECK_INCLUDE_FILE(sys/stat.h HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILE(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILE(unistd.h HAVE_UNISTD_H)

# Check for required functions
CHECK_FUNCTION_EXISTS(fseeko HAVE_FSEEKO)

# LFS Check (thanks to Kitware Systems)
CHECK_C_SOURCE_RUNS("
    #define _LARGEFILE_SOURCE
    #define _LARGEFILE64_SOURCE
    #define _LARGE_FILES
    #define _FILE_OFFSET_BITS 64
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <assert.h>
    #include <stdio.h>

    int main(int argc, char **argv)
    {
      /* check that off_t can hold 2^63 - 1 and perform basic operations... */
    #define OFF_T_64 (((off_t) 1 << 62) - 1 + ((off_t) 1 << 62))
      if (OFF_T_64 % 2147483647 != 1)
        return 1;
    
      // stat breaks on SCO OpenServer
      struct stat buf;
      stat( argv[0], &buf );
      if (!S_ISREG(buf.st_mode))
        return 2;
    
      FILE *file = fopen( argv[0], \"r\" );
      off_t offset = ftello( file );
      fseek( file, offset, SEEK_CUR );
      fclose( file );
      return 0;
    }" TEST_LFS_WORKS)

if (TEST_LFS_WORKS)
    set(_LARGEFILE_SOURCE 1)
    set(_LARGEFILE64_SOURCE 1)
    set(_LARGE_FILES 1)
    set(_FILE_OFFSET_BITS 64)
    set(LFS_CFLAGS -D_LARGE_FILES=1)
endif (TEST_LFS_WORKS)

# Package checks 
find_package(BZip2 REQUIRED)
if(BZIP2_FOUND)
    set(CMAKE_INCLUDE_DIRECTORIES ${BZIP2_INCLUDE_DIR} ${CMAKE_INCLUDE_DIRECTORIES})
    set(CMAKE_REQUIRED_LIBRARIES ${BZIP2_LIBRARIES} ${CMAKE_REQUIRED_LIBRARIES})
    set(HAVE_LIBBZ2 1)
endif(BZIP2_FOUND)

find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
    set(CMAKE_INCLUDE_DIRECTORIES ${ZLIB_INCLUDE_DIRS} ${CMAKE_INCLUDE_DIRECTORIES})
    set(CMAKE_REQUIRED_LIBRARIES ${ZLIB_LIBRARIES} ${CMAKE_REQUIRED_LIBRARIES})
    set(HAVE_LIBZ 1)
endif(ZLIB_FOUND)

# Find Python version 2.4 and above
find_package(PythonInterp REQUIRED)
find_package(PythonLibs REQUIRED)
if(PYTHONINTERP_FOUND AND PYTHONLIBS_FOUND)
    execute_process(
        COMMAND ${PYTHON_EXECUTABLE} -V
        OUTPUT_VARIABLE PYTHON_VERSION ERROR_VARIABLE PYTHON_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE
        )
    string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+)$" PYTHON_VERSION ${PYTHON_VERSION})
    if(NOT ${PYTHON_VERSION} VERSION_LESS "2.4")
        message("-- Python version ${PYTHON_VERSION}.")
        set(HAVE_PYTHON 1)
    endif(NOT ${PYTHON_VERSION} VERSION_LESS "2.4")
endif(PYTHONINTERP_FOUND AND PYTHONLIBS_FOUND)

# Require GCC 4 and above if GCC
if(CMAKE_COMPILER_IS_GNUCC)
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -dumpversion
        OUTPUT_VARIABLE GCC_VERSION ERROR_VARIABLE GCC_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE
        )
    if(NOT ${GCC_VERSION} VERSION_LESS "4")
        message("-- GCC version 4 or above found")
        set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -fvisibility=hidden)
    else(NOT ${GCC_VERSION} VERSION_LESS "4")
        message(FATAL_ERROR "GCC version 4 or above required")
    endif(NOT ${GCC_VERSION} VERSION_LESS "4")
endif(CMAKE_COMPILER_IS_GNUCC)

# Generate config.h
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)
# Generate libmpq.pc
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libmpq.pc.in.cmake ${CMAKE_CURRENT_BINARY_DIR}/libmpq.pc @ONLY)
# Generate libmpq-config
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libmpq-config.in.cmake ${CMAKE_CURRENT_BINARY_DIR}/libmpq-config  @ONLY)

# Make config.h available to the source
include_directories(${CMAKE_CURRENT_BINARY_DIR})

message("PROJECT dir: ${PROJECT_SOURCE_DIR}")

########### install files ###############
#install(FILES ${PROJECT_SOURCE_DIR}/libmpq.pc DESTINATION lib/pkgconfig)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libmpq.pc DESTINATION lib/pkgconfig)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/libmpq-config DESTINATION bin)

add_subdirectory(libmpq)
add_subdirectory(bindings)
add_subdirectory(doc)

############ TODO DEFINES ##############################################
#/* Define to the sub-directory in which libtool stores uninstalled libraries.  */
#undef LT_OBJDIR
#/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS
########################################################################
