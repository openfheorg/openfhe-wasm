#ifndef _OPENFHEWEB_BINFHE_BINFHE_TYPES_EM_H
#define _OPENFHEWEB_BINFHE_BINFHE_TYPES_EM_H

#include "core/wrapped.h"
#include "openfhe.h"

EMSCRIPTEN_BINDINGS(binfhe_types) {
  class_<LWEPrivateKey>("LWEPrivateKey")
      .smart_ptr<std::shared_ptr<LWEPrivateKey>>("LWEPrivateKey");
  class_<LWECiphertext>("LWECiphertext")
      .smart_ptr<std::shared_ptr<LWECiphertext>>("LWECiphertext");
  class_<RingGSWBTKey>("RingGSWBTKey")
      .smart_ptr<std::shared_ptr<RingGSWBTKey>>("RingGSWBTKey");
  class_<RingGSWEvalKey>("RingGSWEvalKey")
      .smart_ptr<std::shared_ptr<RingGSWEvalKey>>("RingGSWEvalKey");
  class_<LWESwitchingKey>("LWESwitchingKey")
      .smart_ptr<std::shared_ptr<LWESwitchingKey>>("LWESwitchingKey");

  enum_<BINFHE_PARAMSET>("BINFHE_PARAMSET")
      .value("TOY", lbcrypto::TOY)
      .value("MEDIUM", lbcrypto::MEDIUM)
      .value("STD128_AP", lbcrypto::STD128_AP)
      .value("STD128_APOPT", lbcrypto::STD128_APOPT)
      .value("STD128", lbcrypto::STD128)
      .value("STD128_OPT", lbcrypto::STD128_OPT)
      .value("STD192", lbcrypto::STD192)
      .value("STD192_OPT", lbcrypto::STD192_OPT)
      .value("STD256", lbcrypto::STD256)
      .value("STD256_OPT", lbcrypto::STD256_OPT)
      .value("STD128Q", lbcrypto::STD128Q)
      .value("STD128Q_OPT", lbcrypto::STD128Q_OPT)
      .value("STD192Q", lbcrypto::STD192Q)
      .value("STD192Q_OPT", lbcrypto::STD192Q_OPT)
      .value("STD256Q", lbcrypto::STD256Q)
      .value("STD256Q_OPT", lbcrypto::STD256Q_OPT)
      .value("SIGNED_MOD_TEST", lbcrypto::SIGNED_MOD_TEST)
      ;
  enum_<BINGATE>("BINGATE")
      .value("OR", OR)
      .value("AND", AND)
      .value("NOR", NOR)
      .value("NAND", NAND)
      .value("XOR_FAST", XOR_FAST)
      .value("XNOR_FAST", XNOR_FAST)
      .value("XOR", XOR)
      .value("XNOR", XNOR);
  enum_<BINFHE_METHOD>("BINFHEMETHOD").value("AP", AP).value("GINX", GINX);
}

#endif //_OPENFHEWEB_BINFHE_BINFHE_TYPES_EM_H
