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

/**
 * @brief Setter for the plaintext modulus.
 * @param CryptoParameters -
 * @return The plaintext modulus.
 */
template<typename Scheme>
void SetWrappedPlaintextModulus(
    CCParams<Scheme> &CryptoParameters, const emscripten::val &ptMod) {
  // assume that the plaintext modulus is < 2^31
  const auto as32t = ptMod.as<uint32_t>();
  CryptoParameters.SetPlaintextModulus(as32t);
}

/**
 * @brief Getter for the plaintext modulus.
 * @param CryptoParameters -
 * @return The plaintext modulus.
 */
template<typename Element>
uint32_t GetWrappedMultiplicativeDepth(const CCParams<Element> &CryptoParameters) {
  // assume that the plaintext modulus is < 2^31
  return (uint32_t) CryptoParameters.GetMultiplicativeDepth();
}

/**
 * @brief Setter for the plaintext modulus.
 * @param CryptoParameters -
 * @return The plaintext modulus.
 */
template<typename Scheme>
void SetWrappedMultiplicativeDepth(
    CCParams<Scheme> &CryptoParameters, const emscripten::val &ptMod) {
  // assume that the plaintext modulus is < 2^31
  const auto as32t = ptMod.as<uint32_t>();
  CryptoParameters.SetMultiplicativeDepth(as32t);
}

template<typename Scheme>
void SetSecurityLevel(
    CCParams<Scheme> &CryptoParameters,
    SecurityLevel security
) {
  CryptoParameters.SetSecurityLevel(security);
}

template<typename Scheme>
void SetRingDim(
    CCParams<Scheme> &CryptoParameters,
    usint ringDim
) {
  CryptoParameters.SetRingDim(ringDim);
}

template<typename Scheme>
void SetScalingModSize(
    CCParams<Scheme> &CryptoParameters,
    uint32_t scalingModSize
) {
  CryptoParameters.SetScalingModSize(scalingModSize);
}

template<typename Scheme>
void SetBatchSize(
    CCParams<Scheme> &CryptoParameters,
    uint32_t batchSize
) {
  CryptoParameters.SetBatchSize(batchSize);
}

template<typename Scheme>
void SetScalingTechnique(
    CCParams<Scheme> &CryptoParameters,
    ScalingTechnique st

) {
  CryptoParameters.SetScalingTechnique(st);
}
template<typename Scheme>
void SetKeySwitchTechnique(
    CCParams<Scheme> &CryptoParameters,
    KeySwitchTechnique kt

) {
  CryptoParameters.SetKeySwitchTechnique(kt);
}

using CKKS = CryptoContextCKKSRNS;
using CCP_CKKS = CCParams<CKKS>;
using BFV = CryptoContextBFVRNS;
using CCP_BFV = CCParams<BFV>;
using BGV = CryptoContextBGVRNS;
using CCP_BGV = CCParams<BGV>;
EMSCRIPTEN_BINDINGS(parameters) {

  class_<CCP_BFV>("CCParamsCryptoContextBFVRNS")
      .smart_ptr<std::shared_ptr<CCP_BFV>>("CCParamsCryptoContextBFVRNS")
      .constructor(&std::make_shared<CCP_BFV>, allow_raw_pointers())
      .function("GetPlaintextModulus", &GetWrappedPlaintextModulus<BFV>)
      .function("SetPlaintextModulus", &SetWrappedPlaintextModulus<BFV>)
      .function("GetMultiplicativeDepth", &GetWrappedMultiplicativeDepth<BFV>)
      .function("SetMultiplicativeDepth", &SetWrappedMultiplicativeDepth<BFV>)
      .function("SetSecurityLevel", &SetSecurityLevel<BFV>)
      .function("SetRingDim", &SetRingDim<BFV>)
      .function("SetScalingModSize", &SetScalingModSize<BFV>)
      .function("SetBatchSize", &SetBatchSize<BFV>)
      .function("SetScalingTechnique", &SetScalingTechnique<BFV>)
      .function("SetKeySwitchTechnique", &SetKeySwitchTechnique<BFV>)
      .function("toString", &GetString<CCP_BFV>);

  class_<CCP_BGV>("CCParamsCryptoContextBGVRNS")
      .smart_ptr<std::shared_ptr<CCP_BGV>>("CCParamsCryptoContextBGVRNS")
      .constructor(&std::make_shared<CCP_BGV>, allow_raw_pointers())
      .function("GetPlaintextModulus", &GetWrappedPlaintextModulus<BGV>)
      .function("SetPlaintextModulus", &SetWrappedPlaintextModulus<BGV>)
      .function("GetMultiplicativeDepth", &GetWrappedMultiplicativeDepth<BGV>)
      .function("SetMultiplicativeDepth", &SetWrappedMultiplicativeDepth<BGV>)
      .function("SetSecurityLevel", &SetSecurityLevel<BGV>)
      .function("SetRingDim", &SetRingDim<BGV>)
      .function("SetScalingModSize", &SetScalingModSize<BGV>)
      .function("SetBatchSize", &SetBatchSize<BGV>)
      .function("SetScalingTechnique", &SetScalingTechnique<BGV>)
      .function("SetKeySwitchTechnique", &SetKeySwitchTechnique<BGV>)
      .function("toString", &GetString<CCP_BGV>);

  class_<CCP_CKKS>("CCParamsCryptoContextCKKSRNS")
      .smart_ptr<std::shared_ptr<CCP_CKKS>>("CCParamsCryptoContextCKKSRNS")
      .constructor(&std::make_shared<CCP_CKKS>, allow_raw_pointers())
      .function("GetPlaintextModulus", &GetWrappedPlaintextModulus<CKKS>)
      .function("SetPlaintextModulus", &SetWrappedPlaintextModulus<CKKS>)
      .function("GetMultiplicativeDepth", &GetWrappedMultiplicativeDepth<CKKS>)
      .function("SetMultiplicativeDepth", &SetWrappedMultiplicativeDepth<CKKS>)
      .function("SetSecurityLevel", &SetSecurityLevel<CKKS>)
      .function("SetRingDim", &SetRingDim<CKKS>)
      .function("SetScalingModSize", &SetScalingModSize<CKKS>)
      .function("SetBatchSize", &SetBatchSize<CKKS>)
      .function("SetScalingTechnique", &SetScalingTechnique<CKKS>)
      .function("SetKeySwitchTechnique", &SetKeySwitchTechnique<CKKS>)
      .function("toString", &GetString<CCP_CKKS>);
}

#endif //OPENFHE_WASM_SRC_CORE_PARAMETERS_H_
