#ifndef _OPENFHEWEB_CORE_WRAPPED_H_
#define _OPENFHEWEB_CORE_WRAPPED_H_

// 64 bit integers cannot be returned directly to JavaScript.
// use a wrapper struct instead
template <typename Element>
struct Wrapped {
  Element value;
};
// override printing to use inner object
template <typename Element>
std::ostream &operator<<(std::ostream &os, const Wrapped<Element> wrapped) {
  os << wrapped.value;
  return os;
}

#endif
