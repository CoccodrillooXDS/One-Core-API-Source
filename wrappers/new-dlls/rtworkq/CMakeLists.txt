
add_definitions(-D__WINESRC__)
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/wine)
include_directories(${REACTOS_SOURCE_DIR}/wrappers/sdk/include/wsdk)
include_directories(${REACTOS_BINARY_DIR}/sdk/include/reactos/wine)
spec2def(rtworkq.dll rtworkq.spec ADD_IMPORTLIB)

set(baseaddress_rtworkq 0x682d0000)

list(APPEND SOURCE
    queue.c
    version.rc
    ${CMAKE_CURRENT_BINARY_DIR}/rtworkq_stubs.c
    ${CMAKE_CURRENT_BINARY_DIR}/rtworkq.def)

add_library(rtworkq SHARED ${SOURCE})
set_module_type(rtworkq win32dll)
target_link_libraries(rtworkq wine)
add_importlibs(rtworkq ole32 combase msvcrt kernelex ntdll)
add_cd_file(TARGET rtworkq DESTINATION reactos/system32 FOR all)
