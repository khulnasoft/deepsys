find_program(PANDOC pandoc)

if (PANDOC)
	add_custom_target(man_deepsys ALL
		COMMAND ${PANDOC} -s -f markdown_github -t man deepsys.md -o ${CMAKE_CURRENT_BINARY_DIR}/deepsys.8
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/deepsys.8
		DESTINATION share/man/man8)

	add_custom_target(man_cdeepsys ALL
		COMMAND ${PANDOC} -s -f markdown_github -t man cdeepsys.md -o ${CMAKE_CURRENT_BINARY_DIR}/cdeepsys.8
		WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
		VERBATIM)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cdeepsys.8
		DESTINATION share/man/man8)
else()
	install(FILES deepsys.8
		DESTINATION share/man/man8)

	install(FILES cdeepsys.8
		DESTINATION share/man/man8)
endif()
