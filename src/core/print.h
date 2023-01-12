#ifndef _OPENFHEWEB_CORE_PRINTH_
#define _OPENFHEWEB_CORE_PRINTH_


/**
 * @brief Get string value from an OPENFHE object.
 * @param object - OPENFHE supported object.
 * @return string to be p.
 */
template <typename Element>
std::string GetString(const Element &object) {
  std::stringstream ss;
  ss << object;
  return ss.str();
}

#endif
