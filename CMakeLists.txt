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
link_directories(${OpenFHE_LIBDIR})
link_libraries(${OpenFHE_LIBRARIES})


if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${OpenFHE_VERSION}")
    message(STATUS "OpenFHE Include Directories: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE Library Directories: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
endif ()

set(NATIVE_SIZE ${OPENFHE_NATIVE_SIZE})
message(STATUS "NATIVE_SIZE set to: " ${NATIVE_SIZE})

add_link_options(
        # for now, exceptions are enabled.
        # they are necessary for JSON serialization to work
        #	-sDISABLE_EXCEPTION_CATCHING


        # See https://github.com/emscripten-core/emscripten/blob/main/src/settings.js for more
        # information
        -sEXCEPTION_DEBUG=1

        -sALLOW_MEMORY_GROWTH=1
        -sERROR_ON_UNDEFINED_SYMBOLS=0
        -sMAXIMUM_MEMORY=4GB
)
add_compile_options("-DOPENFHE_VERSION=${OpenFHE_VERSION}")

### add each of the subdirs of src
add_subdirectory(src/binfhe)
add_subdirectory(src/core)
add_subdirectory(src/pke)

find_package(Doxygen QUIET COMPONENTS dot)
if (DOXYGEN_FOUND)

    add_custom_target(apidocs
            COMMAND sh -c "( cat ${CMAKE_CURRENT_SOURCE_DIR}/doc/doxygen-config && echo PROJECT_NUMBER=${OPENFHE_VERSION} ) | ${DOXYGEN_EXECUTABLE} -"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM)
    message(STATUS "Doxygen and dot are found")

else (DOXYGEN_FOUND)
    message(STATUS "Doxygen and dot (from graphviz) need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)
