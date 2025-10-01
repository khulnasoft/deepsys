include_directories("${JSONCPP_INCLUDE}")

if(NOT WIN32)
    if(NOT APPLE)
        include_directories("${CURL_INCLUDE_DIR}")
    endif()
	include_directories("${CURSES_INCLUDE_DIR}")
endif()

include_directories("${PROJECT_SOURCE_DIR}/common")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libsinsp")
include_directories("${PROJECT_BINARY_DIR}/userspace/deepsys")
include_directories(.)

if(NOT WIN32)
	set(SOURCE_FILES
		fields_info.cpp
		deepsys.cpp)

	set(SOURCE_FILES_CDEEPSYS
		fields_info.cpp
		cdeepsys.cpp)
else()
	set(SOURCE_FILES
		fields_info.cpp
		deepsys.cpp
		win32/getopt.c)

	set(SOURCE_FILES_CDEEPSYS
		fields_info.cpp
		cdeepsys.cpp
		win32/getopt.c)
endif()

add_executable(deepsys ${SOURCE_FILES})
add_executable(cdeepsys ${SOURCE_FILES_CDEEPSYS})

if(NOT WIN32)

	target_link_libraries(deepsys
		sinsp)

	if(USE_BUNDLED_NCURSES)
		add_dependencies(cdeepsys ncurses)
	endif()

	target_link_libraries(cdeepsys
		sinsp
		"${CURSES_LIBRARIES}")

	add_subdirectory(man)

	install(TARGETS deepsys 
		DESTINATION bin)

	install(TARGETS cdeepsys 
		DESTINATION bin)

	install(DIRECTORY chisels
		DESTINATION share/deepsys)

	file(COPY chisels
		DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

else()

	target_link_libraries(deepsys
		sinsp)

	target_link_libraries(cdeepsys
		sinsp)

	target_link_libraries(deepsys odbc32.lib odbccp32.lib)

	target_link_libraries(cdeepsys odbc32.lib odbccp32.lib)

	add_custom_command(TARGET deepsys POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${LUAJIT_SRC}/lua51.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/lua51.dll")

	add_custom_command(TARGET deepsys POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${ZLIB_INCLUDE}/zlib1.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/")

	add_custom_command(TARGET deepsys POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_directory
			"${PROJECT_SOURCE_DIR}/userspace/deepsys/chisels"
			"${PROJECT_BINARY_DIR}/$(Configuration)/chisels")

	add_custom_command(TARGET deepsys POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:deepsys>
			"${PROJECT_BINARY_DIR}/$(Configuration)/deepsys.exe")

	add_custom_command(TARGET cdeepsys POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:cdeepsys>
			"${PROJECT_BINARY_DIR}/$(Configuration)/cdeepsys.exe")

endif()

configure_file(config_deepsys.h.in config_deepsys.h)
