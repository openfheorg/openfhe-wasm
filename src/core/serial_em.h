#ifndef _OPENFHEWEB_CORE_SERIAL_EM_H
#define _OPENFHEWEB_CORE_SERIAL_EM_H

// C++ openfhe serialization options are handled at compile-time
// by the type system.
// Therefore we have to add wrapper methods that select
// the correct method at runtime.
enum class JsSerType { JSON, BINARY };

emscripten::val stringstreamToTypedArray(std::ostringstream &ss) {
  auto str = ss.str();
  return val::global("Uint8Array").new_(emscripten::typed_memory_view(str.length(), str.c_str()));
}

std::istringstream typedArrayToStringstream(const emscripten::val &jsBuf) {
  auto buf = emscripten::vecFromJSArray<uint8_t>(jsBuf);
  return std::istringstream(std::string(buf.begin(), buf.end()));
}

/**
 * @brief Serialize the OPENFHE object from JsBuffer.
 * @param jsBuf - input object as a buffer.
 * @param serType - #BINARY or #JSON
 * @return serialized buffer.
 */
template <typename Element>
emscripten::val SerializeToBuffer(const Element &obj, JsSerType serType) {
  std::ostringstream outputBuffer;

  if (serType == JsSerType::BINARY) {
    Serial::Serialize(obj, outputBuffer, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    Serial::Serialize(obj, outputBuffer, SerType::JSON);
  }

  return stringstreamToTypedArray(outputBuffer);
}

/**
 * @brief Deserialize into the OPENFHE object from JsBuffer.
 * @param jsBuf - input object as a buffer.
 * @param serType - #BINARY or #JSON
 * @return OPENFHE object.
 */
template <typename Element>
Element DeserializeFromBuffer(const emscripten::val &jsBuf, JsSerType serType) {
  Element obj;
  auto stream = typedArrayToStringstream(jsBuf);

  if (serType == JsSerType::BINARY) {
    Serial::Deserialize(obj, stream, SerType::BINARY);
  } else if (serType == JsSerType::JSON) {
    Serial::Deserialize(obj, stream, SerType::JSON);
  }

  return obj;
}

EMSCRIPTEN_BINDINGS(core_serial_em) {
  enum_<JsSerType>("SerType").value("JSON", JsSerType::JSON).value("BINARY", JsSerType::BINARY);
}

#endif
