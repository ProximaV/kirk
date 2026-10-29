# Processor Module: kirk
ida_add_procmod(kirk
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        kirk.hpp
        ins.hpp
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cfg/kirk.cfg")
    copy_cfg(kirk ${CMAKE_CURRENT_SOURCE_DIR}/cfg/kirk.cfg)
endif()

# Deploy procmod and config to IDA user directory (%APPDATA%/Hex-Rays/IDA Pro)
if(DEFINED ENV{APPDATA})
    set(IDA_USER_DIR "$ENV{APPDATA}/Hex-Rays/IDA Pro")

    add_custom_command(TARGET kirk POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/procs"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:kirk>" "${IDA_USER_DIR}/procs/$<TARGET_FILE_NAME:kirk>"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDA_USER_DIR}/cfg"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/cfg/kirk.cfg" "${IDA_USER_DIR}/cfg/kirk.cfg"
        COMMENT "Deploying KIRK procmod and cfg to IDA Pro user directory"
    )
endif()
