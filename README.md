# OpenFHE WebAssembly

`OpenFHE-WASM` is the official web-assembly port of the [OpenFHE library](https://github.com/openfheorg/openfhe-development). `OpenFHE-WASM` currently supports a subset of BGV, BFV, and CKKS API available in the OpenFHE C++ version.

All versions of OpemFHE starting with v1.3.0 are supported.

# Table of Contents
- [Notes specific to OpenFHE-WASM](#notes-specific-to-openfhe-wasm)
- [Build instructions from source](#build-instructions-from-source)
  - [Build the OpenFHE library with Emscripten](#build-the-openfhe-library-with-emscripten)
  - [Build OpenFHE-WASM](#buil-openfhe-wasm)
  - [Running OpenFHE-WASM](#running-web-assembly-unit-tests) 
    - TODO
  - [Sharp Edges](#sharp-edges)

# Notes specific to OpenFHE-WASM

* We have managed to compile `OpenFHE-WASM` using emscripten 3.1.30 through 4.0.8. A more recent version of `modejs` (20 or later) should be used to achieve the best performance.
* The `OpenFHE-WASM` port is somewhat slower (typically 1.5 to 3.x depending on the operation) than the native C++ version of OpenFHE (in g++ or clang++) due to a normal slowdown incurred in web assembly builds (typically 2x) and additional slow-down due to the use of 64-bit arithmetic in PALISADE (64-bit arithmetic is emulated in WASM).
* Web assembly running environment is typically limited to 4GB of RAM.
* `OpenFHE-WASM` does not currently support multi-threading.

# Build instructions from source

## Build the OpenFHE library with Emscripten

1. Install `emscripten` using the instructions at https://emscripten.org/docs/getting_started/downloads.html. We tested v3.1.30 through 4.0.8.
2. Install `NodeJs` if not already installed. We suggest installing NodeJS 20 or later for best runtime results. Check the version using `nodejs -v`.
3. Clone [OpenFHE-development](https://github.com/openfheorg/openfhe-development)
4. `cd` into the cloned directory and create `embuild` directory.
5. Run

```
export PREFIX=~/install/location
mkdir embuild
cd embuild
emcmake cmake .. -DCMAKE_INSTALL_PREFIX=${PREFIX}
emmake make -jN
emmake make install
```

**Note**: 
- `N` is number of cores available on your system.
- `~/install/location` can be any empty directory location where openfhe binaries should be installed. 
- To include the unit tests, examples, or benchmarks, the corresponding cmake flags can be set to "ON" instead of "OFF".

## Build OpenFHE-WASM

1. Clone the `openfhe-wasm` repository and cd into it

2. Run the following commands to build the NodeJS bindings.

```
mkdir build
cd build
emcmake cmake .. -DOpenFHE_DIR=${PREFIX}/lib/OpenFHE
emmake make
```

This should install emscripten libraries in `openfhe-wasm/lib` directory.

3Now run the examples in the following directories using `nodejs`

* `examples/js/binfhe/`
* `examples/js/pke/`

# Running web-assembly unit tests

## Running web-assembly benchmarks

# Typescript Development

# Building

# Notes specific to openfhe-wasm

# Examples

