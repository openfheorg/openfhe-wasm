

include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/binfhe)
include_directories(${PROJECT_SOURCE_DIR}/src)

add_executable(openfhe_binfhe BinFHEContext_em.cpp)
target_link_libraries(openfhe_binfhe ${BINFHELIBS})
target_link_options(openfhe_binfhe PUBLIC
	-s MODULARIZE --bind
)

set_property(
	TARGET openfhe_binfhe
	PROPERTY RUNTIME_OUTPUT_DIRECTORY
	${PROJECT_SOURCE_DIR}/lib
)
