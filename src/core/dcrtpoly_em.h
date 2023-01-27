#ifndef _OPENFHEWEB_CORE_DCRTPOLY_H_
#define _OPENFHEWEB_CORE_DCRTPOLY_H_

#include "wrapped.h"

// emscripten is unable to detect some virtual methods
// explicit wrapper methods are required in these cases

/**
 * @brief Get the element's cyclotomic order
 * @return returns the cyclotomic order of the element as 32bit value.
 */
template <typename Element>
usint GetCyclotomicOrder(const typename Element::Params &params) {
  return params.GetCyclotomicOrder();
}

// Using BigVector backend for now.
// do the M2 or M4 backends apply to WASM?

/**
 * @brief Simple getter method for the ciphertext modulus.
 * @param params Element's params.
 * @return The ciphertext modulus.
 */
template <typename Element>
typename Element::Integer GetModulus(const typename Element::Params &params) {
  return params.GetModulus();
}

EMSCRIPTEN_BINDINGS(DCRTPoly) {
  class_<DCRTPoly::Params>("ElementParams")
      .smart_ptr<std::shared_ptr<DCRTPoly::Params>>("ElementParams")
      .function("GetCyclotomicOrder", &GetCyclotomicOrder<DCRTPoly>)
      .function("GetModulus", &GetModulus<DCRTPoly>)
      .function("toString", &GetString<DCRTPoly::Params>);
  class_<Wrapped<uint64_t>>("UInt64").function("toString", &GetString<Wrapped<uint64_t>>);
}

#endif
