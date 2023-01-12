#ifndef _OPENFHEWEB_BINFHE_SERIAL_EM_H
#define _OPENFHEWEB_BINFHE_SERIAL_EM_H

#include "core/serial_em.h"
// serialization for RingGSWBTKey
// @NOTE: I changed RingGSWBTKey -> RingGSWACCKeyImpl

EMSCRIPTEN_BINDINGS(binfhe_serial_em) {
  emscripten::function("SerializeCryptoContextToBuffer", &SerializeToBuffer<BinFHEContext>);
  emscripten::function("SerializePrivateKeyToBuffer", &SerializeToBuffer<LWEPrivateKey>);
  emscripten::function("SerializeCiphertextToBuffer", &SerializeToBuffer<LWECiphertext>);

  // use shared ptr because some of thse types don't have copy / move constructors
  emscripten::function("SerializeRefreshKeyToBuffer", &SerializeToBuffer<std::shared_ptr<RingGSWACCKeyImpl>>);
  emscripten::function("SerializeSwitchingKeyToBuffer", &SerializeToBuffer<std::shared_ptr<LWESwitchingKey>>);

  emscripten::function("DeserializeCryptoContextFromBuffer", &DeserializeFromBuffer<BinFHEContext>);
  emscripten::function("DeserializePrivateKeyFromBuffer", &DeserializeFromBuffer<LWEPrivateKey>);
  emscripten::function("DeserializeCiphertextFromBuffer", &DeserializeFromBuffer<LWECiphertext>);

  // use shared ptr because some of thse types don't have copy / move constructors
  emscripten::function("DeserializeRefreshKeyFromBuffer", &DeserializeFromBuffer<std::shared_ptr<RingGSWACCKeyImpl>>);
  emscripten::function("DeserializeSwitchingKeyFromBuffer", &DeserializeFromBuffer<std::shared_ptr<LWESwitchingKey>>);
}

#endif
