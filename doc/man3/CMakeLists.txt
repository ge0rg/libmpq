file(GLOB man_MANS_3 *.3)

########### install files ###############
install(FILES ${man_MANS_3} DESTINATION share/man/man3)
