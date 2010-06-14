
set(crypt_buf_gen_SRCS crypt_buf_gen.c)

add_executable(crypt_buf_gen ${crypt_buf_gen_SRCS})

target_link_libraries(crypt_buf_gen mpq)

install(TARGETS crypt_buf_gen DESTINATION bin)
