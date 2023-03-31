/*
 * //==================================================================================
 * // BSD 2-Clause License
 * //
 * // Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
 * //
 * // All rights reserved.
 * //
 * // Author TPOC: contact@openfhe.org
 * //
 * // Redistribution and use in source and binary forms, with or without
 * // modification, are permitted provided that the following conditions are met:
 * //
 * // 1. Redistributions of source code must retain the above copyright notice, this
 * //    list of conditions and the following disclaimer.
 * //
 * // 2. Redistributions in binary form must reproduce the above copyright notice,
 * //    this list of conditions and the following disclaimer in the documentation
 * //    and/or other materials provided with the distribution.
 * //
 * // THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * // AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * // IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * // DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * // FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * // DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * // SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * // CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * // OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * // OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * //==================================================================================
 *
 */


#ifndef OPENFHE_WASM_SRC_CORE_PARAMETERS_H_
#define OPENFHE_WASM_SRC_CORE_PARAMETERS_H_

#include "core/wrapped.h"
#include "openfhe.h"

/**
 * @brief Getter for the plaintext modulus.
 * @param CryptoParameters -
 * @return The plaintext modulus.
 */
template<typename Element>
uint32_t GetWrappedPlaintextModulus(const CCParams<Element> &CryptoParameters) {
  // assume that the plaintext modulus is < 2^31
  return (uint32_t) CryptoParameters.GetPlaintextModulus();
}

EMSCRIPTEN_BINDINGS(parameters) {

  class_<CCParams<CryptoContextBGVRNS >>("CCParamsCryptoContextBGVRNS")
      .smart_ptr<std::shared_ptr<CCParams<CryptoContextBGVRNS>>>("CCParamsCryptoContextBGVRNS")
      .constructor(&std::make_shared<CCParams<CryptoContextBGVRNS>>, allow_raw_pointers())
      .function("GetPlaintextModulus", &GetWrappedPlaintextModulus<CryptoContextBGVRNS>)
      .function("toString", &GetString<CCParams<CryptoContextBGVRNS>>);
}

#endif //OPENFHE_WASM_SRC_CORE_PARAMETERS_H_
