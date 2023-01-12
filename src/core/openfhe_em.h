#ifndef _OPENFHEWEB_CORE_OPENFHE_EM_H
#define _OPENFHEWEB_CORE_OPENFHE_EM_H

#include "core/serial_em.h"

std::vector<int64_t> MakeVectorInt64Clipped(const emscripten::val &val) {
  const auto vec32 = convertJSArrayToNumberVector<int32_t>(val);
  return std::vector<int64_t>(vec32.begin(), vec32.end());
}

EMSCRIPTEN_BINDINGS(core_types) {
  register_vector<int32_t>("VectorInt32").constructor(&convertJSArrayToNumberVector<int32_t>);
  emscripten::function("MakeVectorInt32", &convertJSArrayToNumberVector<int32_t>);

  register_vector<int64_t>("VectorInt64");
  emscripten::function("MakeVectorInt64Clipped", &MakeVectorInt64Clipped);

  register_vector<double>("VectorDouble").constructor(&convertJSArrayToNumberVector<double>);

  class_<BigInteger>("BigInteger")
      .constructor<std::string>()
      .function("DividedBy", &BigInteger::DividedBy)
      .function("ConvertToDouble", &BigInteger::ConvertToDouble)
      .function("ToString", &BigInteger::ToString);

  class_<EncodingParamsImpl>("EncodingParams").smart_ptr<std::shared_ptr<EncodingParamsImpl>>("EncodingParams");
}

#endif
