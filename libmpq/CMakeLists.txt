file(GLOB sources *.c)
file(GLOB headers *.h)

########### next target ###############

set(mpq_LIB_SRCS ${sources})

add_library(mpq SHARED ${mpq_LIB_SRCS})
add_library(mpq_static STATIC ${mpq_LIB_SRCS})

target_link_libraries(mpq ${CMAKE_REQUIRED_LIBRARIES})
set_target_properties(mpq PROPERTIES VERSION 0.4.2)
set_target_properties(mpq_static PROPERTIES OUTPUT_NAME mpq)

########### install files ###############

install(TARGETS mpq LIBRARY DESTINATION lib)
install(TARGETS mpq_static ARCHIVE DESTINATION lib)
install(FILES mpq.h DESTINATION include/libmpq)
