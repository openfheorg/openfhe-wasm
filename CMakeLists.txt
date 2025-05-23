##
## CMakeLists.txt for OPENFHE
##
## This script will build machine-specific header files for compile
## as it generates the Makefile
##

project(openfhe-wasm)
cmake_minimum_required(VERSION 3.5.1)

set(CMAKE_CXX_STANDARD 17)
set(CXX_STANDARD_REQUIRED ON)

find_package(OpenFHE REQUIRED)
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)
link_directories(${OpenFHE_LIBDIR})
link_libraries(${OpenFHE_LIBRARIES})


if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${OpenFHE_VERSION}")
    message(STATUS "OpenFHE Include Directories: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE Library Directories: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else ()
    message(FATAL_ERROR "Could not find OpenFHE. Exiting.")
endif ()

set(NATIVE_SIZE ${OPENFHE_NATIVE_SIZE})
message(STATUS "NATIVE_SIZE set to: " ${NATIVE_SIZE})

if (CMAKE_BUILD_TYPE)
    set(RELEASE_TYPES
            Debug
            Release
            RelWithDebInfo
            MinSizeRel)
    list(FIND RELEASE_TYPES ${CMAKE_BUILD_TYPE} INDEX_FOUND)
    if (${INDEX_FOUND} EQUAL -1)
        message(
                FATAL_ERROR
                "CMAKE_BUILD_TYPE must be one of Debug, Release, RelWithDebInfo, or MinSizeRel"
        )
    endif ()
else ()
    # if no build type is chosen, default to Release mode
    set(CMAKE_BUILD_TYPE Release CACHE STRING
            "Choose the type of build, options are: None, Debug, Release, RelWithDebInfo, or
	MinSizeRel."
            FORCE)
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "In Debug Mode")
    add_link_options(
            # See https://github.com/emscripten-core/emscripten/blob/main/src/settings.js for more information

            -sEXCEPTION_DEBUG=1
            -sASYNCIFY_DEBUG=2
            -sALLOW_MEMORY_GROWTH=1
            -sDISABLE_EXCEPTION_CATCHING=0
            -sERROR_ON_UNDEFINED_SYMBOLS=0
            -sEXCEPTION_DEBUG=true
            -sMAXIMUM_MEMORY=4GB
            -sRUNTIME_LOGGING=true
    )

else ()

    message(STATUS "In Release Mode")
    add_link_options(
            # See https://github.com/emscripten-core/emscripten/blob/main/src/settings.js for more
            # information
            # Original Values
            -sALLOW_MEMORY_GROWTH=1
            -sERROR_ON_UNDEFINED_SYMBOLS=0
            -sMAXIMUM_MEMORY=4GB
            -sDISABLE_EXCEPTION_CATCHING
    )
endif ()


add_compile_options("-DOPENFHE_VERSION=${OpenFHE_VERSION}")

### add each of the subdirs of src
add_subdirectory(src/core)
add_subdirectory(src/pke)

#find_package(Doxygen QUIET COMPONENTS dot)
#if (DOXYGEN_FOUND)
#
#    add_custom_target(apidocs
#            COMMAND sh -c "( cat ${CMAKE_CURRENT_SOURCE_DIR}/doc/doxygen-config && echo PROJECT_NUMBER=${OPENFHE_VERSION} ) | ${DOXYGEN_EXECUTABLE} -"
#            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#            COMMENT "Generating API documentation with Doxygen"
#            VERBATIM)
#    message(STATUS "Doxygen and dot are found")
#else (DOXYGEN_FOUND)
#    message(STATUS "Doxygen and dot (from graphviz) need to be installed to generate the doxygen documentation")
#endif (DOXYGEN_FOUND)