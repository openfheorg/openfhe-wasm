
// OpenFHE Includes
#include "math/hal.h"
#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
using namespace lbcrypto;

// Emscripten includes.
#include <emscripten.h>
#include <emscripten/bind.h>
#include <emscripten/val.h>
using namespace emscripten;

// Local emscripten binding includes.
#include "core/Plaintext_em.h"
#include "core/print.h"
#include "core/exception_em.h"
#include "core/dcrtpoly_em.h"
#include "core/version_em.h"
#include "pubkeylp_em.h"
#include "pke_serial_em.h"
#include "core/backend_em.h"
#include "core/clear_context.h"

/**
 * @brief construct a OPENFHE CryptoContextImpl for the BFVrns Scheme using the
 * scheme's ParamsGen methods.
 * @param plaintextModulus plaintext modulus.
 * @param securityLevel root Hermite factor (lattice security parameter).
 * @param sigma StdDev - distribution parameter for Gaussian noise generation.
 * @param numAdds additive depth for homomorphic computations (assumes
 * numMults and numKeySwitches are set to zero).
 * @param depth numMults - multiplicative depth for homomorphic computations (assumes
 * numAdds and numKeySwitches are set to zero).
 * @param numKeyswitches  key-switching depth for homomorphic computations
 * (assumes numAdds and numMults are set to zero).
 * @param mode secret key distribution mode (RLWE [Gaussian noise] or
 * OPTIMIZED [ternary uniform distribution]).
 * @param maxDepth (default) - the maximum power of secret key for which the
 * relinearization key is generated (by default, it is 2); setting it to a
 * value larger than 2 adds support for homomorphic multiplication w/o
 * relinearization.
 * @param relinWindow (default) - the key switching window (bits in the base for digits)
 * used for digit decomposition (0 - means to use only CRT decomposition).
 * @param dcrtBits (default) - size of "small" CRT moduli.
 * @param n (default) - ring dimension in case the user wants to use a custom ring
 * dimension.
 * @return new context.
 */
template <typename Element>
CryptoContext<Element> GenCryptoContextBFVrns(uint32_t plaintextModulus,
                                              SecurityLevel securityLevel,
                                              double sigma,
                                              uint32_t numAdd,
                                              uint32_t depth,
                                              uint32_t numKeyswitches,
                                              MODE mode) {
  return CryptoContextFactory<Element>::genCryptoContextBFVrns(plaintextModulus, securityLevel, sigma, numAdd, depth,
                                                               numKeyswitches, mode);
}

/**
 * Generate
 * @param batchSize
 * @param plaintextModulus
 * @param securityLevel
 * @param dist
 * @param multDepth
 * @param mode
 * @param maxDepthPreRelin
 * @param modDecompBitLen
 * @param primeModBitLen
 * @param ringDimension
 *
 */
template <typename Element>
CryptoContext<Element> GenCryptoContextBFVrns2(uint32_t batchSize,
                         uint32_t plaintextModulus,
                         SecurityLevel securityLevel,
                         float dist,
                         unsigned int multDepth,
                         MODE mode,
                         int maxDepthPreRelin,
                         uint32_t modDecompBitLen,
                         size_t primeModBitLen,
                         uint32_t ringDimension) {
  EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus, batchSize));

  CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextBFVrns(
      encodingParams, SecurityLevel(securityLevel), dist, 0, multDepth, 0, MODE(mode), maxDepthPreRelin,
      modDecompBitLen, primeModBitLen, ringDimension);

  cc->Enable(ENCRYPTION);
  cc->Enable(LEVELEDSHE);
  cc->Enable(MULTIPARTY);
  return cc;
}

/**
 * @brief Construct a OPENFHE CryptoContextImpl for the BGVrns Scheme.
 *
 * @param multiplicativeDepth the depth of multiplications supported by the
 * scheme (equal to number of towers - 1).
 * @param plaintextModulus the plaintext modulus.
 * @param securityLevel the standard security level we want the scheme to satisfy.
 * @param sigma StdDev - distribution parameter for error distribution.
 * @param maxDepth the maximum power of secret key for which the
 * relinearization key is generated.
 * @param mode RLWE (gaussian distribution) or OPTIMIZED (ternary distribution).
 * @param keySwitchTechnique (default) - key switching technique to use (e.g., HYBRID, GHS or BV).
 * @param ringDim (default) - the ring dimension (if not specified selected automatically
 * based on stdLevel).
 * @param numLargeDigits (default) - the number of big digits to use in HYBRID key
 * switching.
 * @param firstModSize (default) - the bit-length of the first modulus.
 * @param dcrtrBits (default) - the size of the moduli in bits.
 * @param relinWindow (default) - the relinearization windows (used in BV key switching,
 * use 0 for RNS decomposition).
 * @param batchSize (default) - the number of slots being used in the ciphertext.
 * @param msMethod (default) - mod switch method.
 * @return new context
 */
template <typename Element>
CryptoContext<Element> GenCryptoContextBGVrns(usint multiplicativeDepth,
                                              usint plaintextModulus,
                                              SecurityLevel securityLevel,
                                              double sigma,
                                              uint32_t maxDepth,
                                              MODE mode,
                                              KeySwitchTechnique keySwitchTechnique) {
  return CryptoContextFactory<Element>::genCryptoContextBGVrns(multiplicativeDepth, plaintextModulus, securityLevel,
                                                               sigma, maxDepth, mode, keySwitchTechnique);
}

/**
 * @brief Construct a OPENFHE CryptoContextImpl for the CKKS Scheme.
 *
 * @param multiplicativeDepth the depth of multiplications supported by the
 * scheme (equal to number of towers - 1).
 * @param scalingFactorBits the size of the scaling factor in bits.
 * @param batchSize the number of slots being used in the ciphertext.
 * @param securityLevel the standard security level we want the scheme to satisfy.
 * @param ringDim (default) - the ring dimension (if not specified selected automatically
 * based on stdLevel).
 * @param ksTech (default) - key switching technique to use (e.g., HYBRID, GHS or BV).
 * @param rsTech (default) - Scaling technique to use (e.g., APPROXRESCALE or
 * EXACTRESCALE).
 * @param numLargeDigits (default) - the number of big digits to use in HYBRID key
 * switching.
 * @param maxDepth (default) - the maximum power of secret key for which the
 * relinearization key is generated.
 * @param firstModSize (default) - the bit-length of the first modulus.
 * @param relinWindow (default) - the relinearization windows (used in BV key switching,
 * use 0 for RNS decomposition).
 * @param mode (default) - RLWE (gaussian distribution) or OPTIMIZED (ternary
 * distribution).
 * @return new context.
 */
template <typename Element>
CryptoContext<Element> GenCryptoContextCKKS(usint multiplicativeDepth,
                                            usint scaleFactorBits,
                                            usint batchSize,
                                            SecurityLevel securityLevel) {
  return CryptoContextFactory<Element>::genCryptoContextCKKS(multiplicativeDepth, scaleFactorBits, batchSize,
                                                             securityLevel);
}



// TURN FEATURES ON
/**
 * @brief Enable a particular feature for use with this CryptoContextImpl
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param pkeScheme - the feature that should be enabled
 */
template <typename Element>
void Enable(const CryptoContext<Element> cryptoCtx, PKESchemeFeature pkeScheme) {
  cryptoCtx->Enable(pkeScheme);
}

/**
 * @brief KeyGen generates a key pair using this algorithm's KeyGen method.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @return a public/secret key pair.
 */
template <typename Element>
KeyPair<Element> KeyGen(CryptoContext<Element> cryptoCtx) {
  return cryptoCtx->KeyGen();
}

/**
 * @brief Generate key switch hint on a ciphertext for depth 2.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param secretKey is the original private key used for generating
 * ciphertext.
 */
template <typename Element>
void EvalMultKeyGen(const CryptoContext<Element> cryptoCtx, PrivateKey<Element> secretKey) {
  cryptoCtx->EvalMultKeyGen(secretKey);
}

/**
 * @brief constructs a PackedEncoding in this context
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param values Vector of integers
 * @return plaintext
 */
template <typename Element>
Plaintext MakePackedPlaintext(const CryptoContext<Element> cryptoCtx, std::vector<int32_t> values) {
  std::vector<int64_t> values64(values.size());
  for (int i = 0; i < values.size(); i++) {
    values64[i] = values[i];
  };
  return cryptoCtx->MakePackedPlaintext(values64);
}

/**
 * @brief constructs a CKKSPackedEncoding in this context
 * from a vector of real numbers
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param values - input vector of doubles.
 * @param depth - depth used to encode the vector.
 * @param level (default) - level at each the vector will get encrypted.
 * @param params (default) - parameters to be used for the ciphertext.
 * @return plaintext
 */
template <typename Element>
Plaintext MakeCKKSPackedPlaintext(const CryptoContext<Element> cryptoCtx, std::vector<double> values) {
  return cryptoCtx->MakeCKKSPackedPlaintext(values);
}

/**
 * @brief Encrypt a plaintext using a given public key.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param publicKey - public key used for encryption.
 * @param plaintext - copy of the plaintext input. NOTE a copy is passed! That
 * is NOT an error!
 * @return ciphertext (or null on failure)
 */
template <typename Element>
Ciphertext<Element> Encrypt(const CryptoContext<Element> cryptoCtx,
                            PublicKey<Element> publicKey,
                            Plaintext plaintext) {
  return cryptoCtx->Encrypt(publicKey, plaintext);
}

/**
 * @brief Method for decrypting plaintext using LBC.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param &secretKey private key used for decryption.
 * @param &ciphertext ciphertext id decrypted.
 * @return Plaintext as the decoding result.
 */
template <typename Element>
Plaintext Decrypt(const CryptoContext<Element> cryptoCtx,
                  const PrivateKey<Element> secretKey,
                  Ciphertext<Element> ciphertext) {
  Plaintext result;
  cryptoCtx->Decrypt(secretKey, ciphertext, &result);
  return result;
}

// NOTE: explicit wrapper methods are required for certain type conversions.
// for example, emscripten is unable to recognize that
// Ciphertext can be implicitly converted to ConstCiphertext
// hopefully emscripten fixes this one day.

/**
 * @brief Define the interface for homomorphic addition of
 * ciphertexts.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext1 - the input ciphertext.
 * @param ciphertext2 - the input ciphertext.
 * @return the new resultant ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalAddCipherCipher(const CryptoContext<Element> &cryptoCtx,
                                        Ciphertext<Element> ciphertext1,
                                        Ciphertext<Element> ciphertext2) {
  return cryptoCtx->EvalAdd(ciphertext1, ciphertext2);
}

/**
 * @brief Define the interface for homomorphic multiplication of
 * ciphertexts.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext1 - the input ciphertext.
 * @param ciphertext2 - the input ciphertext.
 * @return the new resultant ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalMultCipherCipher(const CryptoContext<Element> &cryptoCtx,
                                         Ciphertext<Element> ciphertext1,
                                         Ciphertext<Element> ciphertext2) {
  return cryptoCtx->EvalMult(ciphertext1, ciphertext2);
}

/**
 * @brief Define the interface for homomorphic multiplication of
 * ciphertexts.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext1 - the input ciphertext.
 * @param pt - the input plaintext.
 * @return the new resultant ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalMultCipherPlaintext(const CryptoContext<Element> &cryptoCtx,
                                         Ciphertext<Element> ciphertext1,
                                         Plaintext pt) {
  return cryptoCtx->EvalMult(ciphertext1, pt);
}

/**
 * @brief Define the interface for homomorphic multiplication of
 * ciphertexts available in CKKS.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext1 - the input ciphertext.
 * @param constant - Contant multiplier.
 * @return the new resultant ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalMultCipherConstant(const CryptoContext<Element> &cryptoCtx,
                                           Ciphertext<Element> ciphertext1,
                                           double constant) {
  return cryptoCtx->EvalMult(ciphertext1, constant);
}

/**
 * @brief Define the interface for homomorphic substraction of
 * ciphertexts.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext1 - the input ciphertext.
 * @param ciphertext2 - the input ciphertext.
 * @return the new resultant ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalSubCipherCipher(const CryptoContext<Element> &cryptoCtx,
                                        Ciphertext<Element> ciphertext1,
                                        Ciphertext<Element> ciphertext2) {
  return cryptoCtx->EvalSub(ciphertext1, ciphertext2);
}

/**
 * @brief Define the interface for homomorphic negate of
 * ciphertexts.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext - the input ciphertext.
 * @return the new resultant ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalNegate(const CryptoContext<Element> &cryptoCtx, Ciphertext<Element> ciphertext) {
  return cryptoCtx->EvalNegate(ciphertext);
}

/**
 * @brief Moves i-th slot to slot 0
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext -  Input ciphertext.
 * @param index - the index. of the slot.
 * @return resulting ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalAtIndex(const CryptoContext<Element> &cryptoCtx,
                                Ciphertext<Element> ciphertext,
                                int32_t index) {
  return cryptoCtx->EvalAtIndex(ciphertext, index);
}

/**
 * @brief OPENFHE ModReduce method used only for BGVrns.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext - Input ciphertext.
 * @return mod reduced ciphertext.
 */
template <typename Element>
Ciphertext<Element> ModReduce(const CryptoContext<Element> &cryptoCtx, Ciphertext<Element> ciphertext) {
  return cryptoCtx->ModReduce(ciphertext);
}

/**
 * @brief Function for evaluating a sum of all components.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext the input ciphertext.
 * @param batchSize size of the batch.
 * @return the resultant ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalSum(const CryptoContext<Element> &cryptoCtx, Ciphertext<Element> ciphertext, usint batchSize) {
  return cryptoCtx->EvalSum(ciphertext, batchSize);
}

/**
 * @brief Evaluates inner product in batched encoding.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext1 - first ciphertext.
 * @param ciphertext2 - second ciphertext.
 * @param batchSize - size of the batch to be summed up.
 * @return resulting ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalInnerProduct(const CryptoContext<Element> &cryptoCtx,
                                     Ciphertext<Element> ciphertext1,
                                     Ciphertext<Element> ciphertext2,
                                     usint batchSize) {
  return cryptoCtx->EvalInnerProduct(ciphertext1, ciphertext2, batchSize);
}

/**
 * @details OPENFHE function for evaluating multiplication on
 * ciphertext followed by relinearization operation (at the end). It computes
 * the multiplication in a binary tree manner. Also, it reduces the number of
 * elements in the ciphertext to two after each multiplication.
 * Currently it assumes that the consecutive two input arguments have
 * total depth smaller than the supported depth. Otherwise, it throws an
 * error.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertextList  is the ciphertext list.
 * @return new ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalMultMany(const CryptoContext<Element> &cryptoCtx, emscripten::val ciphertextList) {
  auto ciphertextVec = vecFromJSArray<Ciphertext<Element>>(ciphertextList);
  return cryptoCtx->EvalMultMany(ciphertextVec);
}

/**
 * @brief Merges multiple ciphertexts with encrypted results in slot 0 into a single
 * ciphertext The slot assignment is done based on the order of ciphertexts in
 * the vector.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertextVector vector of ciphertexts to be merged.
 * @return resulting ciphertext.
 */
template <typename Element>
Ciphertext<Element> EvalMerge(const CryptoContext<Element> &cryptoCtx, emscripten::val ciphertextVector) {
  auto ciphertextVec = vecFromJSArray<Ciphertext<Element>>(ciphertextVector);
  return cryptoCtx->EvalMerge(ciphertextVec);
}

/**
 * @brief OPENFHE EvalLinearWSum method to compute a linear
 * weighted sum.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertexts a list of ciphertexts.
 * @param constants a list of weights.
 * @return new ciphertext containing the weighted sum.
 */
template <typename Element>
Ciphertext<Element> EvalLinearWSum(const CryptoContext<Element> &cryptoCtx,
                                   emscripten::val ciphertexts,
                                   emscripten::val constants) {
  return cryptoCtx->EvalLinearWSum(vecFromJSArray<Ciphertext<Element>>(ciphertexts),
                                   convertJSArrayToNumberVector<double>(constants));
}

/**
 * @brief this is a wrapper for the hoisted automorphism
 * pre-computation step, in schemes BV, GHS, and Hybrid.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext the input ciphertext on which to do the precomputation
 * (digit decomposition).
 */
template <typename Element>
std::shared_ptr<std::vector<Element>> EvalFastRotationPrecompute(const CryptoContext<Element> &cryptoCtx,
                                                            Ciphertext<Element> ciphertext) {
  return cryptoCtx->EvalFastRotationPrecompute(ciphertext);
}

/**
 * @brief Function for the automorphism and key switching step of
 * hoisted automorphisms.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext the input ciphertext to perform the automorphism on.
 * @param index the index of the rotation. Positive indices correspond to
 * left rotations and negative indices correspond to right rotations.
 * @param m is the cyclotomic order.
 * @param digits the digit decomposition created by
 * EvalFastRotationPrecompute at the precomputation step.
 */
template <typename Element>
Ciphertext<Element> EvalFastRotation(const CryptoContext<Element> &cryptoCtx,
                                     Ciphertext<Element> ciphertext,
                                     const usint index,
                                     const usint m,
                                     const std::shared_ptr<std::vector<Element>> digits) {
  return cryptoCtx->EvalFastRotation(ciphertext, index, m, digits);
}

/**
 * @brief Proxy Re Encryption mechanism for OPENFHE.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param evalKey - evaluation key from the PRE keygen method.
 * @param ciphertext - vector of shared pointers to encrypted Ciphertext.
 * @param publicKey (default) - the public key of the recipient of the re-encrypted.
 * ciphertext.
 * @return resulting ciphertext after the re-encryption operation.
 */
template <typename Element>
Ciphertext<Element> ReEncrypt2(const CryptoContext<Element> &cryptoCtx,
                               EvalKey<Element> evalKey,
                               Ciphertext<Element> ciphertext) {
  return cryptoCtx->ReEncrypt(evalKey, ciphertext);
}

// explicit wrapper methods are required to use
// non-member (static) functions as member functions

/**
 * @brief flush EvalMultKey cache for a given context.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 */
template <typename Element>
void ClearEvalMultKeys(const CryptoContext<Element> &cryptoCtx) {
  cryptoCtx->ClearEvalMultKeys();
}

/**
 * @brief flush EvalAutomorphismKey cache for a given id.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 */
template <typename Element>
void ClearEvalAutomorphismKeys(const CryptoContext<Element> &cryptoCtx) {
  cryptoCtx->ClearEvalAutomorphismKeys();
}

/**
 * @brief flush EvalSumKey cache.
 * @param cryptoCtx - Reference to CryptoContext from JS.
 */
template <typename Element>
void ClearEvalSumKeys(const CryptoContext<Element> &cryptoCtx) {
  cryptoCtx->ClearEvalSumKeys();
}

/**
 * @brief Add the given map of keys to the map, replacing the
 * existing map if there
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param mapToInsert - (usint, EvalKey) pair.
 */
template <typename Element>
void InsertEvalSumKey(const CryptoContext<Element> &cryptoCtx,
                      const std::shared_ptr<std::map<usint, EvalKey<Element>>> mapToInsert) {
  cryptoCtx->InsertEvalSumKey(mapToInsert);
}

/**
 * @brief Add the given map of keys to the map, replacing the
 * existing map if there
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param evalKeyVector - EvalKey vector.
 */
template <typename Element>
void InsertEvalMultKey(const CryptoContext<Element> &cryptoCtx, const emscripten::val &evalKeyVector) {
  const auto vectorToInsert = vecFromJSArray<EvalKey<Element>>(evalKeyVector);
  cryptoCtx->InsertEvalMultKey(vectorToInsert);
}

/**
 * @brief Serialize all EvalMultKeys made in a given context
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param serType - type of serialization JSON or BINARY.
 * @return (internal) - string from ostringstream as buffer.
 */
template <typename Element>
emscripten::val SerializeEvalMultKeyToBuffer(const CryptoContext<Element> &cryptoCtx, JsSerType serType) {
  std::ostringstream outputBuffer;

  if (serType == JsSerType::BINARY) {
    cryptoCtx->SerializeEvalMultKey(outputBuffer, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    cryptoCtx->SerializeEvalMultKey(outputBuffer, SerType::JSON);
  }

  return stringstreamToTypedArray(outputBuffer);
}

/**
 * @brief Serialize all EvalAutoKeys made in a given context
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param serType - type of serialization JSON or BINARY.
 * @return (internal) - string from ostringstream as buffer.
 */
template <typename Element>
emscripten::val SerializeEvalAutomorphismKeyToBuffer(const CryptoContext<Element> &cryptoCtx, JsSerType serType) {
  std::ostringstream outputBuffer;

  if (serType == JsSerType::BINARY) {
    cryptoCtx->SerializeEvalAutomorphismKey(outputBuffer, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    cryptoCtx->SerializeEvalAutomorphismKey(outputBuffer, SerType::JSON);
  }

  return stringstreamToTypedArray(outputBuffer);
}

/**
 * @brief Serialize all EvalSumKeys made in a given context
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param serType - type of serialization JSON or BINARY.
 * @return (internal) - string from ostringstream as buffer.
 */
template <typename Element>
emscripten::val SerializeEvalSumKeyToBuffer(const CryptoContext<Element> &cryptoCtx, JsSerType serType) {
  std::ostringstream outputBuffer;

  if (serType == JsSerType::BINARY) {
    cryptoCtx->SerializeEvalSumKey(outputBuffer, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    cryptoCtx->SerializeEvalSumKey(outputBuffer, SerType::JSON);
  }

  return stringstreamToTypedArray(outputBuffer);
}

/**
 * @brief deserialize all EvalMult keys in the serialization
 * deserialized keys silently replace any existing matching keys
 * deserialization will create CryptoContextImpl if necessary
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param jsBuf (internal) - string with a serialization.
 * @param serType - type of serialization JSON or BINARY.
 */
template <typename Element>
void DeserializeEvalMultKeyFromBuffer(const CryptoContext<Element> &cryptoCtx,
                                      const emscripten::val &jsBuf,
                                      JsSerType serType) {
  auto stream = typedArrayToStringstream(jsBuf);

  if (serType == JsSerType::BINARY) {
    cryptoCtx->DeserializeEvalMultKey(stream, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    cryptoCtx->DeserializeEvalMultKey(stream, SerType::JSON);
  }
}

/**
 * @brief deserialize all EvalAuto keys in the serialization
 * deserialized keys silently replace any existing matching keys
 * deserialization will create CryptoContextImpl if necessary
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param jsBuf (internal) - string with a serialization.
 * @param serType - type of serialization JSON or BINARY.
 */
template <typename Element>
void DeserializeEvalAutomorphismKeyFromBuffer(const CryptoContext<Element> &cryptoCtx,
                                              const emscripten::val &jsBuf,
                                              JsSerType serType) {
  auto stream = typedArrayToStringstream(jsBuf);

  if (serType == JsSerType::BINARY) {
    cryptoCtx->DeserializeEvalAutomorphismKey(stream, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    cryptoCtx->DeserializeEvalAutomorphismKey(stream, SerType::JSON);
  }
}

/**
 * @brief deserialize all EvalSum keys in the serialization
 * deserialized keys silently replace any existing matching keys
 * deserialization will create CryptoContextImpl if necessary
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param jsBuf (internal) - string with a serialization.
 * @param serType - type of serialization JSON or BINARY.
 */
template <typename Element>
void DeserializeEvalSumKeyFromBuffer(const CryptoContext<Element> &cryptoCtx,
                                              const emscripten::val &jsBuf,
                                              JsSerType serType) {
  auto stream = typedArrayToStringstream(jsBuf);

  if (serType == JsSerType::BINARY) {
    cryptoCtx->DeserializeEvalSumKey(stream, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    cryptoCtx->DeserializeEvalSumKey(stream, SerType::JSON);
  }
}

// this must be an explicit wrapper method because
// default arguments don't count as overloads

/**
 * @brief Generates evaluation keys for a list of indices
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param privateKey - private key.
 * @param indexList - list of indices.
 * @param publicKey (default) - public key (used in NTRU schemes).
 */
template <typename Element>
void EvalAtIndexKeyGen(const CryptoContext<Element> &cryptoCtx,
                       const PrivateKey<Element> privateKey,
                       const emscripten::val indexList) {
  auto indexVec = vecFromJSArray<int32_t>(indexList);
  cryptoCtx->EvalAtIndexKeyGen(privateKey, indexVec);
}

/**
 * @brief Generates the key map to be used by evalsum.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param privateKey private key.
 * @param publicKey public key (used in NTRU schemes).
 */
template <typename Element>
void EvalSumKeyGen1(const CryptoContext<Element> &cryptoCtx, const PrivateKey<Element> privateKey) {
  cryptoCtx->EvalSumKeyGen(privateKey);
}

/**
 * @brief Threshold FHE: Generation of a public key derived
 * from a previous joined public key (for prior secret shares) and the secret
 * key share of the current party.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param pk - joined public key from prior parties.
 * @param makeSparse (default) - set to true if ring reduce by a factor of 2 is to be
 * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
 * @param fresh (default) - set to true if proxy re-encryption is used in the multi-party
 * protocol or star topology is used
 * @return key pair including the secret share for the current party and
 * joined public key
 */
template <typename Element>
KeyPair<Element> MultipartyKeyGen(const CryptoContext<Element> &cryptoCtx, const PublicKey<Element> pk) {
  return cryptoCtx->MultipartyKeyGen(pk);
}
// custom wrapper methods for convenience.
// BEFORE:
// const ciphertextAdd123Vec = new module.CiphertextDCRTPoly();
// ciphertextAdd123Vec.push_back(ciphertextAdd123);
// cc.MultipartyDecryptLead(kp1.secretKey, ciphertextAdd123Vec);
// AFTER:
// cc.MultipartyDecryptLead(kp1.secretKey, [ciphertextAdd123]);

/**
 * @brief Threshold FHE: Method for decryption operation run by the lead decryption
 * client
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param privateKey secret key share used for decryption.
 * @param ciphertextVecJs ciphertext vector.
 * @return new ciphertext vector.
 */
template <typename Element>
std::vector<Ciphertext<Element>> MultipartyDecryptLead(const CryptoContext<Element> &cryptoCtx,
                                                       const PrivateKey<Element> privateKey,
                                                       const emscripten::val &ciphertextVecJs) {
  const auto ciphertextVec = vecFromJSArray<Ciphertext<Element>>(ciphertextVecJs);
  return cryptoCtx->MultipartyDecryptLead(privateKey, ciphertextVec);
}

/**
 * @brief Threshold FHE: "Partial" decryption computed by all parties except for the
 * lead one
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param privateKey secret key share used for decryption.
 * @param ciphertextVecJs ciphertext that is being decrypted.
 */
template <typename Element>
std::vector<Ciphertext<Element>> MultipartyDecryptMain(const CryptoContext<Element> &cryptoCtx,
                                                       const PrivateKey<Element> privateKey,
                                                       const emscripten::val &ciphertextVecJs) {
  const auto ciphertext = vecFromJSArray<Ciphertext<Element>>(ciphertextVecJs);
  return cryptoCtx->MultipartyDecryptMain(privateKey, ciphertext);
}

/**
 * @brief Threshold FHE: Method for combining the partially decrypted ciphertexts
 * and getting the final decryption in the clear.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param &partialCiphertextVecJs vector of "partial" decryptions.
 * @return the decoding result.
 */
template <typename Element>
Plaintext MultipartyDecryptFusion(const CryptoContext<Element> &cryptoCtx,
                                  const emscripten::val &partialCiphertextVecJs) {
  const auto partialCiphertextVec = vecFromJSArray<Ciphertext<Element>>(partialCiphertextVecJs);
  Plaintext plaintext;
  cryptoCtx->MultipartyDecryptFusion(partialCiphertextVec, &plaintext);
  return plaintext;
}



// note that in JS, the shared pointer is automatically is constructed.

/**
 * @brief Get EvalSumKey map.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param keyId - string id to be found.
 * @return the EvalSum key map.
 */
template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> GetEvalSumKeyMap(const CryptoContext<Element> &cryptoCtx,
                                                                      const std::string &keyId) {
  return std::make_shared<std::map<usint, EvalKey<Element>>>(cryptoCtx->GetEvalSumKeyMap(keyId));
}

/**
 * @brief Reduces the size of ciphertext modulus to minimize the
 * communication cost before sending the encrypted result for decryption.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ciphertext - input ciphertext
 * @param numTowers - number of CRT limbs after compressing (default is 1)
 * @return compressed ciphertext
 */
template <typename Element>
Ciphertext<Element> Compress(const CryptoContext<Element> &cryptoCtx, Ciphertext<Element> ciphertext, usint numTowers) {
  return cryptoCtx->Compress(ciphertext, numTowers);
}

/**
 * @brief Gets the batch size of the given cryptocontext
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @return int
 */
template<typename Element>
int GetBatchSize(const CryptoContext<Element> &cryptoCtx) {
    return cryptoCtx->GetEncodingParams()->GetBatchSize();
}

template<typename Element>
int GetPlaintextModulus(const CryptoContext<Element> &cryptoCtx) {
    return cryptoCtx->GetEncodingParams()->GetPlaintextModulus();
}

using CC = CryptoContextImpl<DCRTPoly>;
EMSCRIPTEN_BINDINGS(CryproContext) {
  emscripten::function("GenCryptoContextBFVrns", &GenCryptoContextBFVrns<DCRTPoly>);
  emscripten::function(
      "GenCryptoContextBFVrns",
      select_overload<CryptoContext<DCRTPoly>(uint32_t, uint32_t, SecurityLevel, float, unsigned int, MODE, int, uint32_t, size_t, uint32_t)>(
          &GenCryptoContextBFVrns2<DCRTPoly>));

  emscripten::function("GenCryptoContextBGVrns", &GenCryptoContextBGVrns<DCRTPoly>);
  emscripten::function("GenCryptoContextCKKS", &GenCryptoContextCKKS<DCRTPoly>);
  emscripten::function(
      "GenCryptoContextCKKS",
      select_overload<CryptoContext<DCRTPoly>(usint, usint, usint, SecurityLevel, usint, ScalingTechnique,
                                              KeySwitchTechnique, uint32_t, int, usint, usint, MODE)>(
          &CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS));

  emscripten::register_vector<Ciphertext<DCRTPoly>>("VectorCiphertextDCRTPoly");
  emscripten::register_vector<EvalKey<DCRTPoly>>("VectorEvalKeyDCRTPoly");
  emscripten::register_vector<DCRTPoly>("VectorDCRTPoly")
      .smart_ptr<std::shared_ptr<std::vector<DCRTPoly>>>("VectorDCRTPoly");

  emscripten::register_map<usint, EvalKey<DCRTPoly>>("UnsignedIntToEvalKey_DCRTPolyMap")
      .smart_ptr<std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>>>("UnsignedIntToEvalKey_DCRTPolyMap");

  class_<CryptoContextImpl<DCRTPoly>>("CryptoContext_DCRTPoly")
      .smart_ptr<CryptoContext<DCRTPoly>>("CryptoContext_DCRTPoly")
      .constructor(&std::make_shared<CryptoContextImpl<DCRTPoly>>, allow_raw_pointers())
      // ignoring mult-feature Enable() for now
      .function("Enable", select_overload<void(PKESchemeFeature)>(&CC::Enable))
      .function("KeyGen", &CC::KeyGen)
      // select_overload() required because the other overload is deprecated
      .function("ReKeyGen",
                select_overload<EvalKey<DCRTPoly>(const PublicKey<DCRTPoly>, const PrivateKey<DCRTPoly>) const>(
                    &CC::ReKeyGen))
      .function("MultipartyKeyGen", &MultipartyKeyGen<DCRTPoly>)
      .function("KeySwitchGen", &CC::KeySwitchGen)
      .function("MultiKeySwitchGen", &CC::MultiKeySwitchGen)
      .function("MultiAddEvalKeys", &CC::MultiAddEvalKeys)
      .function("MultiAddEvalMultKeys", &CC::MultiAddEvalMultKeys)
      .function("MultiAddEvalSumKeys", &CC::MultiAddEvalSumKeys)
      .function("InsertEvalSumKey", &InsertEvalSumKey<DCRTPoly>)
      .function("InsertEvalMultKey", &InsertEvalMultKey<DCRTPoly>)
      .function("MultiMultEvalKey", &CC::MultiMultEvalKey)
      .function("MultiEvalSumKeyGen", &CC::MultiEvalSumKeyGen)
      .function("MultipartyDecryptLead", &MultipartyDecryptLead<DCRTPoly>)
      .function("MultipartyDecryptMain", &MultipartyDecryptMain<DCRTPoly>)
      .function("MultipartyDecryptFusion", &MultipartyDecryptFusion<DCRTPoly>)
      .function("GetCryptoParameters", &CC::GetCryptoParameters)
      .function("EvalMultKeyGen", &CC::EvalMultKeyGen)
      // emscripten DOES support overloading based on # of params
      // 3 args
      .function("EvalAtIndexKeyGen", &CC::EvalAtIndexKeyGen)
      // 2 args
      .function("EvalAtIndexKeyGen", &EvalAtIndexKeyGen<DCRTPoly>)
      .function("MakePackedPlaintext", &CC::MakePackedPlaintext)
      .function("MakeCKKSPackedPlaintext", &MakeCKKSPackedPlaintext<DCRTPoly>)
      // select_overload() required because the other overload is deprecated
      .function("Encrypt", select_overload<Ciphertext<DCRTPoly>(PublicKey<DCRTPoly>, Plaintext)>(&CC::Encrypt))
      .function("ReEncrypt", &ReEncrypt2<DCRTPoly>)
      .function("Decrypt", &Decrypt<DCRTPoly>, allow_raw_pointers())
      .function("EvalAddCipherCipher", EvalAddCipherCipher<DCRTPoly>)
      .function("EvalMultCipherCipher", EvalMultCipherCipher<DCRTPoly>)
      .function("EvalMultCipherPlaintext", EvalMultCipherPlaintext<DCRTPoly>)
      .function("EvalSubCipherCipher", EvalSubCipherCipher<DCRTPoly>)
      .function("EvalMultCipherConstant", EvalMultCipherConstant<DCRTPoly>)
      .function("EvalNegate", &EvalNegate<DCRTPoly>)
      .function("EvalAtIndex", &EvalAtIndex<DCRTPoly>)
      .function("EvalFastRotationPrecompute", &EvalFastRotationPrecompute<DCRTPoly>)
      .function("EvalFastRotation", &EvalFastRotation<DCRTPoly>)
      .function("EvalSum", &EvalSum<DCRTPoly>)
      .function("EvalInnerProduct", &EvalInnerProduct<DCRTPoly>)
      .function("EvalMultMany", &EvalMultMany<DCRTPoly>)
      .function("EvalMerge", &EvalMerge<DCRTPoly>)
      .function("EvalLinearWSum", &EvalLinearWSum<DCRTPoly>)
      .function("ModReduce", &ModReduce<DCRTPoly>)
      .function("EvalSumKeyGen", &EvalSumKeyGen1<DCRTPoly>)
      .function("GetEvalSumKeyMap", &GetEvalSumKeyMap<DCRTPoly>)
      .function("GetRingDimension", &CC::GetRingDimension)
      .function("Compress", &Compress<DCRTPoly>)
      .function("GetBatchSize", &GetBatchSize<DCRTPoly>)
      .function("GetPlaintextModulus", &GetPlaintextModulus<DCRTPoly>)
    // serialization
      .function("ClearEvalMultKeys", ClearEvalMultKeys<DCRTPoly>)
      .function("ClearEvalAutomorphismKeys", ClearEvalAutomorphismKeys<DCRTPoly>)
      .function("ClearEvalSumKeys", ClearEvalAutomorphismKeys<DCRTPoly>)
      .function("SerializeEvalMultKeyToBuffer", &SerializeEvalMultKeyToBuffer<DCRTPoly>)
      .function("SerializeEvalAutomorphismKeyToBuffer", &SerializeEvalAutomorphismKeyToBuffer<DCRTPoly>)
      .function("SerializeEvalSumKeyToBuffer", &SerializeEvalSumKeyToBuffer<DCRTPoly>)
      .function("DeserializeEvalMultKeyFromBuffer", &DeserializeEvalMultKeyFromBuffer<DCRTPoly>)
      .function("DeserializeEvalAutomorphismKeyFromBuffer", &DeserializeEvalAutomorphismKeyFromBuffer<DCRTPoly>)
      .function("DeserializeEvalSumKeyFromBuffer", &DeserializeEvalSumKeyFromBuffer<DCRTPoly>);
}




