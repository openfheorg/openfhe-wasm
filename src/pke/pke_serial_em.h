#ifndef _OPENFHEWEB_PKE_SERIAL_EM_H
#define _OPENFHEWEB_PKE_SERIAL_EM_H

#include "core/serial_em.h"
#include

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

EMSCRIPTEN_BINDINGS(serial) {
  emscripten::function("SerializeCryptoContextToBuffer", &SerializeToBuffer<CryptoContext<DCRTPoly>>,
                       allow_raw_pointers());
  emscripten::function("SerializePublicKeyToBuffer", &SerializeToBuffer<PublicKey<DCRTPoly>>, allow_raw_pointers());
  emscripten::function("SerializePrivateKeyToBuffer", &SerializeToBuffer<PrivateKey<DCRTPoly>>, allow_raw_pointers());
  emscripten::function("SerializeCiphertextToBuffer", &SerializeToBuffer<Ciphertext<DCRTPoly>>);
  emscripten::function("DeserializeCryptoContextFromBuffer", &DeserializeCryptoContextFromBuffer<DCRTPoly>,
                       allow_raw_pointers());
  emscripten::function("DeserializePublicKeyFromBuffer", &DeserializeFromBuffer<PublicKey<DCRTPoly>>);
  emscripten::function("DeserializePrivateKeyFromBuffer", &DeserializeFromBuffer<PrivateKey<DCRTPoly>>);
  emscripten::function("DeserializeCiphertextFromBuffer", &DeserializeFromBuffer<Ciphertext<DCRTPoly>>);
}

#endif
