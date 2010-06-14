file(GLOB man_MANS_1 *.1)

########### install files ###############
install(FILES ${man_MANS_1} DESTINATION share/man/man1)
