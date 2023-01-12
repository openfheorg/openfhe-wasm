//
// Created by iq on 6/16/22.
//

#ifndef CLEAR_CONTEXT_H
#define CLEAR_CONTEXT_H

#include "openfhe.h"

void ReleaseAllContexts(){
  lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
}


EMSCRIPTEN_BINDINGS(clear_contexts) {
  emscripten::function("ReleaseAllContexts", &ReleaseAllContexts);
};

#endif  // CLEAR_CONTEXT_H
