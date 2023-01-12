//
// Created by iq on 6/16/22.
//

#ifndef BACKEND_EM_H
#define BACKEND_EM_H

#include <string>

#if NATIVEINT == 64
  std::string m_BackendSize = "64";
#else  // NATIVEINT == 128
  std::string m_BackendSize = "128";
#endif

std::string GetBackendSize() { return m_BackendSize; }

EMSCRIPTEN_BINDINGS(backend) {
    emscripten::function("GetBackendSize", &GetBackendSize);
};

#endif  // BACKEND_EM_H
