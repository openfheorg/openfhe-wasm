#ifndef _OPENFHEWEB_CORE_EXCEPTION_EM_H
#define _OPENFHEWEB_CORE_EXCEPTION_EM_H

#include <emscripten.h>
#include <emscripten/bind.h>

std::string getExceptionMessage(int exceptionPtr) {
  return std::string(reinterpret_cast<std::exception *>(exceptionPtr)->what());
}

EMSCRIPTEN_BINDINGS(exception) { emscripten::function("getExceptionMessage", &getExceptionMessage); }

#endif
