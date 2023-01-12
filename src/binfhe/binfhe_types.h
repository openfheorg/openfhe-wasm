#ifndef _OPENFHEWEB_BINFHE_BINFHE_TYPES_EM_H
#define _OPENFHEWEB_BINFHE_BINFHE_TYPES_EM_H

EMSCRIPTEN_BINDINGS(binfhe_types) {
  class_<LWEPrivateKey>("LWEPrivateKey").smart_ptr<std::shared_ptr<LWEPrivateKey>>("LWEPrivateKey");
  class_<LWECiphertext>("LWECiphertext").smart_ptr<std::shared_ptr<LWECiphertext>>("LWECiphertext");
  class_<RingGSWBTKey>("RingGSWBTKey").smart_ptr<std::shared_ptr<RingGSWBTKey>>("RingGSWBTKey");
  class_<RingGSWEvalKey>("RingGSWEvalKey").smart_ptr<std::shared_ptr<RingGSWEvalKey>>("RingGSWEvalKey");
  class_<LWESwitchingKey>("LWESwitchingKey").smart_ptr<std::shared_ptr<LWESwitchingKey>>("LWESwitchingKey");

  enum_<BINFHE_PARAMSET>("BINFHE_PARAMSET")
      .value("TOY", TOY)
      .value("STD128", STD128)
      .value("STD128_AP", STD128_AP)
      .value("STD192", STD192)
      .value("STD256", STD256)
      .value("STD128Q", STD128Q)
      .value("STD192Q", STD192Q)
      .value("STD256Q", STD256Q)
      .value("SIGNED_MOD_TEST", SIGNED_MOD_TEST);
  enum_<BINGATE>("BINGATE")
      .value("OR", OR)
      .value("AND", AND)
      .value("NOR", NOR)
      .value("NAND", NAND)
      .value("XOR_FAST", XOR_FAST)
      .value("XNOR_FAST", XNOR_FAST)
      .value("XOR", XOR)
      .value("XNOR", XNOR);
  enum_<BINFHE_METHOD>("BINFHE_METHOD").value("AP", AP).value("GINX", GINX);
}

#endif
