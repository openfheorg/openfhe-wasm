#ifndef _OPENFHEWEB_PKE_SERIAL_EM_H
#define _OPENFHEWEB_PKE_SERIAL_EM_H

#include "core/serial_em.h"

using namespace lbcrypto;

/**
 * @brief Deserialize into the CryptoContext from JsBuffer.
 * @param jsBuf - input object as a buffer.
 * @param serType - #BINARY or #JSON
 * @return nullptr - in case of exception.
 * @return CryptoContext.
 */
template <typename Element>
CryptoContext<Element> DeserializeCryptoContextFromBuffer(const emscripten::val &jsBuf, JsSerType serType) {
  CryptoContext<Element> cc;
  auto stream = typedArrayToStringstream(jsBuf);

  try {
    if (serType == JsSerType::BINARY) {
      cereal::PortableBinaryInputArchive archive(stream);
      archive(cc);
    } else {
      cereal::JSONInputArchive archive(stream);
      archive(cc);
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return nullptr;
  }

  auto getCC = CryptoContextFactory<Element>::GetContext(cc->GetCryptoParameters(), cc->GetEncryptionAlgorithm(),
                                                         cc->getSchemeId());

  return getCC;
}

void DeserializeCryptoContextFromFile(std::string path, JsSerType serType){

}


template <typename Element>
bool GetContextSer() {
  return SERIALIZE_PRECOMPUTE;
}

template <typename Element>
void SetContextSer(const bool ctxtSer) {
  SERIALIZE_PRECOMPUTE = ctxtSer;
}

EMSCRIPTEN_BINDINGS(serial) {
  emscripten::function("SetContextSer", &SetContextSer<DCRTPoly>);
  emscripten::function("GetContextSer", &GetContextSer<DCRTPoly>);

  emscripten::function("SerializeCryptoContextToBuffer", &SerializeToBuffer<CryptoContext<DCRTPoly>>,
                       allow_raw_pointers());
  emscripten::function("SerializePublicKeyToBuffer", &SerializeToBuffer<LPPublicKey<DCRTPoly>>, allow_raw_pointers());
  emscripten::function("SerializePrivateKeyToBuffer", &SerializeToBuffer<LPPrivateKey<DCRTPoly>>, allow_raw_pointers());
  emscripten::function("SerializeCiphertextToBuffer", &SerializeToBuffer<Ciphertext<DCRTPoly>>);
  emscripten::function("DeserializeCryptoContextFromBuffer", &DeserializeCryptoContextFromBuffer<DCRTPoly>,
                       allow_raw_pointers());
  emscripten::function("DeserializePublicKeyFromBuffer", &DeserializeFromBuffer<LPPublicKey<DCRTPoly>>);
  emscripten::function("DeserializePrivateKeyFromBuffer", &DeserializeFromBuffer<LPPrivateKey<DCRTPoly>>);
  emscripten::function("DeserializeCiphertextFromBuffer", &DeserializeFromBuffer<Ciphertext<DCRTPoly>>);
}

#endif
