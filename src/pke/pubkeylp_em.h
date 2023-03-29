#ifndef _OPENFHEWEB_PKE_PUBKEYLP_EM_H
#define _OPENFHEWEB_PKE_PUBKEYLP_EM_H

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

template<typename Element>
std::string GetEncodingType(const CiphertextImpl<Element> &ciphertext) {
  std::stringstream ss;
  ss << ciphertext.GetEncodingType();
  return ss.str();
}

EMSCRIPTEN_BINDINGS(pke_publey) {
  class_<CryptoObject<DCRTPoly >>("CryptoObject_DCRTPoly")
      .function("GetKeyTag", &CryptoObject<DCRTPoly>::GetKeyTag)
      .function("GetCryptoParameters", &CryptoObject<DCRTPoly>::GetCryptoParameters)
      .function("GetCryptoContext", &CryptoObject<DCRTPoly>::GetCryptoContext);
  class_<PublicKeyImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("PublicKey_DCRTPoly")
      .smart_ptr<PublicKey<DCRTPoly>>("PublicKey_DCRTPoly");
  class_<PrivateKeyImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("PrivateKey_DCRTPoly")
      .smart_ptr<PrivateKey<DCRTPoly>>("PrivateKey_DCRTPoly");
  class_<EvalKeyImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("EvalKey_DCRTPoly")
      .smart_ptr<EvalKey<DCRTPoly>>("EvalKey_DCRTPoly");
  class_<CiphertextImpl<DCRTPoly>, base<CryptoObject<DCRTPoly>>>("Ciphertext_DCRTPoly")
      .smart_ptr<Ciphertext<DCRTPoly>>("Ciphertext_DCRTPoly")
      .smart_ptr<ConstCiphertext<DCRTPoly>>("ConstCiphertext_DCRTPoly")
      .function("GetEncodingType", &GetEncodingType<DCRTPoly>)
      .function("toString", &GetString<CiphertextImpl<DCRTPoly>>);


  /////////////////////////////////////////////////////////////////
  //Non-Cryptoparams
  /////////////////////////////////////////////////////////////////
  class_<KeyPair<DCRTPoly>>("KeyPair_DCRTPoly")
      .function("good", &KeyPair<DCRTPoly>::good)
      .property("secretKey", &KeyPair<DCRTPoly>::secretKey)
      .property("publicKey", &KeyPair<DCRTPoly>::publicKey);

  enum_<KeySwitchTechnique>("KeySwitchTechnique").value("BV", BV).value("HYBRID", HYBRID);

  /////////////////////////////////////////////////////////////////
  //Various implementations of CC-Params
  /////////////////////////////////////////////////////////////////
  class_<CCParams<CryptoContextBGVRNS>>("CryptoParameters_BGVRNS")
      .smart_ptr<std::shared_ptr<CCParams<CryptoContextBGVRNS>>>("CryptoParameters_CryptoContextBGVRNS")
      .function("GetPlaintextModulus", &GetWrappedPlaintextModulus<CryptoContextBGVRNS>)
      .function("toString", &GetString<CCParams<CryptoContextBGVRNS>>);

}

#endif
