cmake_minimum_required(VERSION 3.10)
project(ava LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)

set (LIBARGO_SRCS
	api.cpp
	asn.cpp
	buffer.cpp
	channel.cpp
	driver.cpp
	logger.cpp
	socket.cpp
	udpchannel.cpp
	uri.cpp
)
set (PUB_HDRS
	iapi.h
	idriver.h
)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
	include(GNUInstallDirs)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	add_compile_options(
		-fvisibility=hidden
		-Wno-deprecated-declarations
		-Wno-deprecated-register
	)
	find_package(Threads REQUIRED)
endif()

add_library(libargo SHARED ${LIBARGO_SRCS})

set_target_properties(libargo PROPERTIES PREFIX "")
set_target_properties(libargo PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
set_target_properties(libargo PROPERTIES PUBLIC_HEADER "${PUB_HDRS}")

target_link_libraries(libargo Threads::Threads)

install(TARGETS libargo EXPORT libargo
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/argo
	RUNTIME       DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	add_definitions(
		-D_WIN32_WINNT=0x0601
		-DNOMINMAX
		-DVC_EXTRALEAN
		-DWIN32_LEAN_AND_MEAN
		-D_CRT_SECURE_NO_WARNINGS
		-D_MBCS
		-D_SCL_SECURE_NO_WARNINGS
		-D_WINSOCK_DEPRECATED_NO_WARNINGS
	)
	target_compile_definitions(libargo PUBLIC _WINDLL)
	target_link_libraries(libargo wsock32 ws2_32)
	set(CMAKE_PDB_OUTPUT_DIRECTORY "${CMAKE_INSTALL_BINDIR}")
	install(FILES libargo $<TARGET_PDB_FILE:argo> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
endif()

add_executable(testargo testargo.cpp)
target_link_libraries(testargo libargo)
install (TARGETS testargo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(argo argo.cpp)
target_link_libraries(argo libargo)
install(TARGETS argo RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
