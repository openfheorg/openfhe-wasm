

include_directories(${OPENFHE_INCLUDE}/core)
include_directories(${OPENFHE_INCLUDE}/pke)
include_directories(${PROJECT_SOURCE_DIR}/src)

add_executable(
	openfhe_pke CryptoContext_em.cpp
)
add_executable(
	openfhe_pke_es6 CryptoContext_em.cpp
)

target_link_libraries(openfhe_pke ${PKELIBS})
target_link_libraries(openfhe_pke_es6 ${PKELIBS})

target_link_options(openfhe_pke PUBLIC
	-s MODULARIZE --bind
)
target_link_options(openfhe_pke_es6 PUBLIC
	-sEXPORT_ES6=1
	-sMODULARIZE=1
	--bind
)

set_property(
	TARGET openfhe_pke
	PROPERTY RUNTIME_OUTPUT_DIRECTORY
	${PROJECT_SOURCE_DIR}/lib
)
set_property(
	TARGET openfhe_pke_es6
	PROPERTY RUNTIME_OUTPUT_DIRECTORY
	${PROJECT_SOURCE_DIR}/lib
)
