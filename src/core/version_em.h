#ifndef _OPENFHEWEB_CORE_VERSION_H_
#define _OPENFHEWEB_CORE_VERSION_H_

#include <emscripten.h>
#include <emscripten/bind.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(openfhe_version) {
	emscripten::function("GetOPENFHEVersion", &GetOPENFHEVersion);
}

#endif
