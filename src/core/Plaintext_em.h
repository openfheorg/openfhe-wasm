#ifndef _OPENFHEWEB_CORE_PLAINTEXT_EM_H_
#define _OPENFHEWEB_CORE_PLAINTEXT_EM_H_

#include "openfhe_em.h"
#include "print.h"

/**
 * @brief SetLength of the plaintext to the given size.
 * @param plaintext - plaintext to set its length with given size.
 * @param size - number of elements.
 */
void SetLength(Plaintext plaintext, size_t size) { plaintext->SetLength(size); }

/**
 * @brief Get method to return log2 of estimated precision
 * @param plaintext - input plaintext
 * @return double value
 */
double GetLogPrecision(Plaintext plaintext) { return plaintext->GetLogPrecision(); }

/**
 * @brief Get string from a plaintext.
 * @param plaintext - input plaintext.
 * @return string.
 */
std::string PlaintextToString(Plaintext plaintext) {
  std::stringstream ss;
  ss << plaintext;
  return ss.str();
}

/**
 * @brief Get packed values in the for of 32 bit integers from a plaintext.
 * @param plaintext - input plaintext.
 * @return vector of int32_t.
 */
std::vector<int32_t> GetPackedValue(Plaintext plaintext) {
  auto int64Vec = plaintext->GetPackedValue();
  std::vector<int32_t> retVec(int64Vec.begin(), int64Vec.end());
  return retVec;
}

/**
 * @brief Get Coef. packed values in the for of 32 bit integers from a plaintext.
 * @param plaintext - input plaintext.
 * @return vector of int32_t.
 */
std::vector<int32_t> GetCoefPackedValue(Plaintext plaintext) {
  auto int64Vec = plaintext->GetCoefPackedValue();
  std::vector<int32_t> retVec(int64Vec.begin(), int64Vec.end());
  return retVec;
}

EMSCRIPTEN_BINDINGS(core) {
  class_<PlaintextImpl>("Plaintext")
      .smart_ptr<Plaintext>("Plaintext")
      .function("SetLength", &PlaintextImpl::SetLength)
      .function("GetLength", &PlaintextImpl::GetLength)
      .function("GetLogPrecision", &PlaintextImpl::GetLogPrecision)
      .function("toString", &GetString<PlaintextImpl>)
      .function("GetPackedValue", &GetPackedValue)
      .function("GetCoefPackedValue", &GetCoefPackedValue)
      .function("GetRealPackedValue", &PlaintextImpl::GetRealPackedValue);

  // Enumerations
  enum_<SecurityLevel>("SecurityLevel")
      .value("HEStd_128_classic", HEStd_128_classic)
      .value("HEStd_192_classic", HEStd_192_classic)
      .value("HEStd_256_classic", HEStd_256_classic)
      .value("HEStd_NotSet", HEStd_NotSet);

  enum_<SecretKeyDist>("SecretKeyDist")
      .value("GAUSSIAN", GAUSSIAN)
      .value("UNIFORM_TERNARY", UNIFORM_TERNARY)
      .value("SPARSE_TERNARY", SPARSE_TERNARY);

  enum_<PKESchemeFeature>("PKESchemeFeature")
      .value("PKE", PKE)
      .value("PRE", PRE)
      .value("SHE", LEVELEDSHE)
      .value("FHE", FHE)
      .value("MULTIPARTY", MULTIPARTY)
      .value("ADVANCEDSHE", ADVANCEDSHE);

  enum_<ScalingTechnique>("ScalingTechnique")
      .value("FIXEDMANUAL", FIXEDMANUAL)
      .value("FLEXIBLEAUTO", FLEXIBLEAUTO)
      .value("FIXEDAUTO", FIXEDAUTO);
}

#endif
