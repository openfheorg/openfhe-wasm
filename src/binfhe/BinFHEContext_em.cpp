
// OpenFHE Includes
#include "binfhecontext.h"
#include "binfhecontext-ser.h"
using namespace lbcrypto;

// Emscripten includes.
#include <emscripten.h>
#include <emscripten/bind.h>
using namespace emscripten;

// Local emscripten binding includes.
#include "binfhe_serial_em.h"
#include "binfhe_types.h"
#include "core/exception_em.h"

/**
 * @brief Creates a crypto context using custom parameters.
 * Should be used with care (only for advanced users familiar with LWE
 * parameter selection).
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param n lattice parameter for additive LWE scheme
 * @param N ring dimension for RingGSW/RLWE used in bootstrapping
 * @param q modulus for additive LWE
 * @param Q modulus for RingGSW/RLWE used in bootstrapping
 * @param std standard deviation
 * @param baseKS the base used for key switching
 * @param baseG the gadget base used in bootstrapping
 * @param baseR the base used for refreshing
 * @param method the bootstrapping method (AP or GINX)
 * @return creates the cryptocontext
 * @NOTE: CHANGED -> changed args ordering bc the OpenFHE implementation changed.
 */
void GenerateBinFHEContext(BinFHEContext* cryptoCtx,
                           uint32_t n,
                           uint32_t N,
                           int32_t q,
                           int32_t Q,
                           int32_t qKS,
                           double std,
                           uint32_t baseKS,
                           uint32_t baseG,
                           uint32_t baseR,
                           BINFHE_METHOD method = GINX) {
  cryptoCtx->GenerateBinFHEContext(n, N, (const NativeInteger)q, (const NativeInteger)Q,
                                   std, baseKS, baseG, baseR, method);
}

/**
 * @brief Creates a crypto context using predefined parameters sets. Recommended for
 * most users.
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param set the parameter set: TOY, MEDIUM, STD128, STD192, STD256
 * @param method the bootstrapping method (AP or GINX)
 * @return create the cryptocontext
 */
void GenerateBinFHEContext2(BinFHEContext& cryptoCtx, BINFHE_PARAMSET params) { cryptoCtx.GenerateBinFHEContext(params); }

/**
 * @brief Encrypts a bit using a secret key (symmetric key encryption)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param sk - the secret key
 * @param &m - the plaintext
 * @param output - FRESH to generate fresh ciphertext, BOOTSTRAPPED to
 * generate a refreshed ciphertext (default)
 * @return a shared pointer to the ciphertext
 */
LWECiphertext Encrypt(BinFHEContext* cryptoCtx, LWEPrivateKey pk, uint32_t m) {
  return cryptoCtx->Encrypt(pk, (LWEPlaintext)m);
}

/**
 * @brief Decrypts a ciphertext using a secret key
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param sk the secret key
 * @param ct the ciphertext
 * @param *result plaintext as unsigned int.
 */
uint32_t Decrypt(BinFHEContext* cryptoCtx, LWEPrivateKey sk, LWECiphertext ct) {
  LWEPlaintext result;
  cryptoCtx->Decrypt(sk, ct, &result);
  return result;
}

/**
 * @brief Generates boostrapping keys
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param sk secret key
 */
void BTKeyGen(BinFHEContext* cryptoCtx, LWEPrivateKey sk) { cryptoCtx->BTKeyGen(sk); }

/**
 * @brief Generates a switching key to go from a secret key with (Q,N) to a secret
 * key with (q,n)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param sk new secret key
 * @param skN old secret key
 * @return a shared pointer to the switching key
 * @NOTE: CHANGED -> changed LWESwitchingKey -> LWESwitchingKeyImpl
 */
std::shared_ptr<LWESwitchingKeyImpl> KeySwitchGen(BinFHEContext* cryptoCtx, LWEPrivateKey sk, LWEPrivateKey skN) {
  return cryptoCtx->KeySwitchGen(sk, skN);
}

/**
 * @brief Loads bootstrapping keys in the context (typically after deserializing)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param BSkey - first element of struct with the bootstrapping keys.
 * @param KSkey - second element of strct with the bootstrapping keys.
 * @NOTE: CHANGED -> changed :
 *      - LWESwitchingKey (added impl)
 *      - RingGSWBTKey changed to RingGSWACCKeyImpl
 */
void BTKeyLoad(BinFHEContext& cryptoCtx, std::shared_ptr<RingGSWACCKeyImpl> BSkey, std::shared_ptr<LWESwitchingKeyImpl> KSkey) {
  cryptoCtx.BTKeyLoad({BSkey, KSkey});
}

/**
 * @brief Evaluates a binary gate (calls bootstrapping as a subroutine)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XNOR
 * @param ct1 first ciphertext
 * @param ct2 second ciphertext
 * @return a shared pointer to the resulting ciphertext
 */
LWECiphertext EvalBinGate(BinFHEContext* cryptoCtx, BINGATE gate, LWECiphertext ct1, LWECiphertext ct2) {
  return cryptoCtx->EvalBinGate(gate, ct1, ct2);
}

/**
 * @brief Bootstraps a ciphertext (without performing any operation)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ct1 ciphertext to be bootstrapped
 * @return a shared pointer to the resulting ciphertext
 */
LWECiphertext Bootstrap(BinFHEContext* cryptoCtx, LWECiphertext ct1) { return cryptoCtx->Bootstrap(ct1); }

/**
 * @brief Evaluates NOT gate
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ct1 the input ciphertext
 * @return a shared pointer to the resulting ciphertext
 */
LWECiphertext EvalNOT(BinFHEContext* cryptoCtx, LWECiphertext ct1) { return cryptoCtx->EvalNOT(ct1); }

EMSCRIPTEN_BINDINGS(binfhe) {
  class_<BinFHEContext>("BinFHEContext")
      .constructor<>()
      .function("GenerateBinFHEContext",
                select_overload<void(BINFHE_PARAMSET, BINFHE_METHOD)>(&BinFHEContext::GenerateBinFHEContext),
                allow_raw_pointers())
      .function("GenerateBinFHEContext", &GenerateBinFHEContext, allow_raw_pointers())
      .function("GenerateBinFHEContext", &GenerateBinFHEContext2)

      .function("Encrypt", &Encrypt, allow_raw_pointers())

      .function("Decrypt", &Decrypt, allow_raw_pointers())
      .function("BTKeyGen", BTKeyGen, allow_raw_pointers())
      .function("BTKeyLoad", BTKeyLoad)
      .function("KeySwitchGen", KeySwitchGen, allow_raw_pointers())

      .function("EvalBinGate", &EvalBinGate, allow_raw_pointers())
      .function("Bootstrap", &Bootstrap, allow_raw_pointers())
      .function("EvalNOT", &EvalNOT, allow_raw_pointers())
      .function("KeyGen", &BinFHEContext::KeyGen)
      .function("KeyGenN", &BinFHEContext::KeyGenN)

      .function("GetRefreshKey", &BinFHEContext::GetRefreshKey)
      .function("ClearBTKeys", &BinFHEContext::ClearBTKeys)
      .function("GetRefreshKey", &BinFHEContext::GetRefreshKey)
      .function("GetSwitchKey", &BinFHEContext::GetSwitchKey)
      .function("GetParams", &BinFHEContext::GetParams)
      .function("GetLWEScheme", &BinFHEContext::GetLWEScheme)
      .function("SerializedObjectName", &BinFHEContext::SerializedObjectName)

      .class_function("SerializedVersion", &BinFHEContext::SerializedVersion);
}
