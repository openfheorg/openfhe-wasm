#ifndef _OPENFHEWEB_PKE_PUBKEYLP_EM_H
#define _OPENFHEWEB_PKE_PUBKEYLP_EM_H

#include "core/wrapped.h"

/**
 * @brief Getter for the plaintext modulus.
 * @param lpCryptoParameters -
 * @return The plaintext modulus.
 */
template <typename Element>
uint32_t GetWrappedPlaintextModulus(const LPCryptoParameters<Element> &lpCryptoParameters) {
  // assume that the plaintext modulus is < 2^31
  return (uint32_t)lpCryptoParameters.GetPlaintextModulus();
}

template <typename Element>
std::string GetEncodingType(const CiphertextImpl<Element> &ciphertext) {
  std::stringstream ss;
  ss << ciphertext.GetEncodingType();
  return ss.str();
}

EMSCRIPTEN_BINDINGS(pke_publeylp) {
  class_<CryptoObject<DCRTPoly>>("CryptoObject_DCRTPoly")
      .function("GetKeyTag", &CryptoObject<DCRTPoly>::GetKeyTag)
      .function("GetCryptoParameters", &CryptoObject<DCRTPoly>::GetCryptoParameters)
      .function("GetCryptoContext", &CryptoObject<DCRTPoly>::GetCryptoContext);
  class_<LPPublicKeyImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("LPPublicKey_DCRTPoly")
      .smart_ptr<LPPublicKey<DCRTPoly>>("LPPublicKey_DCRTPoly");
  class_<LPPrivateKeyImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("LPPrivateKey_DCRTPoly")
      .smart_ptr<LPPrivateKey<DCRTPoly>>("LPPrivateKey_DCRTPoly");
  class_<LPEvalKeyImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("LPEvalKey_DCRTPoly")
      .smart_ptr<LPEvalKey<DCRTPoly>>("LPEvalKey_DCRTPoly");
  class_<CiphertextImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("Ciphertext_DCRTPoly")
      .smart_ptr<Ciphertext<DCRTPoly>>("Ciphertext_DCRTPoly")
      .smart_ptr<ConstCiphertext<DCRTPoly>>("ConstCiphertext_DCRTPoly")
      .function("GetEncodingType", &GetEncodingType<DCRTPoly>)
      .function("toString", &GetString<CiphertextImpl<DCRTPoly>>);
  class_<LPCryptoParameters<DCRTPoly>>("LPCryptoParameters_DCRTPoly")
      .smart_ptr<shared_ptr<LPCryptoParameters<DCRTPoly>>>("LPCryptoParameters_DCRTPoly")
      .function("GetElementParams", &LPCryptoParameters<DCRTPoly>::GetElementParams)
      .function("GetPlaintextModulus", &GetWrappedPlaintextModulus<DCRTPoly>)
      .function("GetRelinWindow", &LPCryptoParameters<DCRTPoly>::GetRelinWindow)
      .function("toString", &GetString<LPCryptoParameters<DCRTPoly>>);
  class_<LPKeyPair<DCRTPoly>>("LPKeyPair_DCRTPoly")
      .function("good", &LPKeyPair<DCRTPoly>::good)
      .property("secretKey", &LPKeyPair<DCRTPoly>::secretKey)
      .property("publicKey", &LPKeyPair<DCRTPoly>::publicKey);

  enum_<KeySwitchTechnique>("KeySwitchTechnique").value("BV", BV).value("GHS", GHS).value("HYBRID", HYBRID);
}

#endif
