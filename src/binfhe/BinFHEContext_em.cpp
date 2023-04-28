// Palisade Includes
#include "binfhe/binfhecontext.h"
#include "binfhe/binfhecontext-ser.h"
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
 *
    Creates a crypto context using custom parameters. Should be used with care (only for advanced users familiar with LWE parameter selection).

    @param n – lattice parameter for additive LWE scheme
    @param N – ring dimension for RingGSW/RLWE used in bootstrapping
    @param &q – modulus for additive LWE
    @param &Q – modulus for RingGSW/RLWE used in bootstrapping
    @param std – standard deviation
    @param baseKS – the base used for key switching
    @param baseG – the gadget base used in bootstrapping
    @param baseR – the base used for refreshing
    @param method – the bootstrapping method (DM or CGGI)
 */
void GenerateBinFHEContext1(
    BinFHEContext *cryptoCtx,
    uint32_t n,
    uint32_t N,
    const NativeInteger &q,
    const NativeInteger &Q,
    double std,
    uint32_t baseKS,
    uint32_t baseG,
    uint32_t baseR,
    BINFHE_METHOD method = GINX
) {
  cryptoCtx->GenerateBinFHEContext(
      n,
      N,
      (const NativeInteger) q,
      (const NativeInteger) Q,
      std,
      baseKS,
      baseG,
      baseR,
      method
      );
}

/**
 * Creates a crypto context using custom parameters. Should be used with care (only for advanced users familiar with LWE parameter selection).
  @param set – the parameter set: TOY, MEDIUM, STD128, STD192, STD256
  @param arbFunc – whether need to evaluate an arbitrary function using functional bootstrapping
  @param logQ – log(input ciphertext modulus)
  @param N – ring dimension for RingGSW/RLWE used in bootstrapping
  @param method – the bootstrapping method (DM or CGGI)
  @param timeOptimization – whether to use dynamic bootstrapping technique
 */

void GenerateBinFHEContext2(
    BinFHEContext *cryptoCtx,
    BINFHE_PARAMSET set,
    bool arbFunc,
    uint32_t logQ,
    int64_t N,
    BINFHE_METHOD method,
    bool timeOptimization
) {
  cryptoCtx->GenerateBinFHEContext(set, arbFunc, logQ, N, method, timeOptimization);
}
/**
 * Creates a crypto context using predefined parameters sets. Recommended for most users.
  @param set – the parameter set: TOY, MEDIUM, STD128, STD192, STD256
  @param method – the bootstrapping method (DM or CGGI)
 */
void GenerateBinFHEContext3(
    BinFHEContext *cryptoCtx,
    BINFHE_PARAMSET set,
    BINFHE_METHOD method
) {
  cryptoCtx->GenerateBinFHEContext(set, method);
}

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
LWECiphertext Encrypt(BinFHEContext *cryptoCtx, LWEPrivateKey pk, uint32_t m) {
  return cryptoCtx->Encrypt(pk, (LWEPlaintext) m);
}

/**
 * @brief Decrypts a ciphertext using a secret key
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param sk the secret key
 * @param ct the ciphertext
 * @param *result plaintext as unsigned int.
 */
uint32_t Decrypt(BinFHEContext *cryptoCtx, LWEPrivateKey sk, LWECiphertext ct) {
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
void BTKeyGen(BinFHEContext *cryptoCtx, LWEPrivateKey sk) { cryptoCtx->BTKeyGen(sk); }

/**
 * @brief Generates a switching key to go from a secret key with (Q,N) to a secret
 * key with (q,n)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param sk new secret key
 * @param skN old secret key
 * @return a shared pointer to the switching key
 */
std::shared_ptr<LWESwitchingKeyImpl> KeySwitchGen(
    BinFHEContext *cryptoCtx,
    ConstLWEPrivateKey sk,
    ConstLWEPrivateKey skN) {
  return cryptoCtx->KeySwitchGen(sk, skN);
}

/**
 * @brief Loads bootstrapping keys in the context (typically after deserializing)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param BSkey - first element of struct with the bootstrapping keys.
 * @param KSkey - second element of strct with the bootstrapping keys.
 */
void BTKeyLoad(BinFHEContext &cryptoCtx,
               const RingGSWBTKey BSkey
) {
  cryptoCtx.BTKeyLoad(BSkey);
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
LWECiphertext EvalBinGate(BinFHEContext *cryptoCtx, BINGATE gate, LWECiphertext ct1, LWECiphertext ct2) {
  return cryptoCtx->EvalBinGate(gate, ct1, ct2);
}

/**
 * @brief Bootstraps a ciphertext (without performing any operation)
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ct1 ciphertext to be bootstrapped
 * @return a shared pointer to the resulting ciphertext
 */
LWECiphertext Bootstrap(BinFHEContext *cryptoCtx, LWECiphertext ct1) { return cryptoCtx->Bootstrap(ct1); }

/**
 * @brief Evaluates NOT gate
 *
 * @param cryptoCtx - Reference to CryptoContext from JS.
 * @param ct1 the input ciphertext
 * @return a shared pointer to the resulting ciphertext
 */
LWECiphertext EvalNOT(BinFHEContext *cryptoCtx, LWECiphertext ct1) { return cryptoCtx->EvalNOT(ct1); }

EMSCRIPTEN_BINDINGS(binfhe) {
  class_<BinFHEContext>("BinFHEContext")
      .constructor<>()

      .function("GenerateBinFHEContext", &GenerateBinFHEContext1, allow_raw_pointers())
      .function("GenerateBinFHEContext", &GenerateBinFHEContext2, allow_raw_pointers())
      .function("GenerateBinFHEContext", &GenerateBinFHEContext3, allow_raw_pointers())

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
