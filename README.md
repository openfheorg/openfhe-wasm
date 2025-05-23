# OpenFHE WebAssembly (Work in Progress)

`OpenFHE-WASM` is the official web-assembly port of the [OpenFHE library](https://github.com/openfheorg/openfhe-development). `OpenFHE-WASM` currently supports a subset of BGV, BFV, and CKKS API available in the OpenFHE C++ version.

All versions of OpenFHE starting with v1.3.0 are supported.

# Table of Contents
- [Build instructions from source](#build-instructions-from-source)
  - [Building the OpenFHE library with Emscripten](#building-the-openfhe-library-with-emscripten)
  - [Running web-assembly unit tests](#running-web-assembly-unit-tests)
  - [Running web-assembly benchmarks](#running-web-assembly-benchmarks)
  - [Running automatically converted C++ examples](#running-automatically-converted-c-examples)
  - [Building OpenFHE-WASM](#building-openfhe-wasm)
  - [Running OpenFHE-WASM Examples](#running-openfhe-wasm-examples)
- [Notes specific to OpenFHE WebAssmebly](#notes-specific-to-openfhe-webassembly)

# Build instructions from source

## Building the OpenFHE library with Emscripten

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

## Running web-assembly unit tests

Compile OpenFHE in the `embuild` directory using the following CMake flags
```
emcmake cmake .. -DBUILD_UNITTESTS=ON -DCMAKE_INSTALL_PREFIX=~/install/location
```

Run unit tests using `nodejs`:
```
nodejs unittest/binfhe_tests.js
nodejs unittest/core_tests.js
nodejs unittest/pke_tests.js
```

## Running web-assembly benchmarks

Compile OpenFHE in the `embuild` directory using the following CMake flags
```
emcmake cmake .. -DBUILD_BENCHMARKS=ON -DCMAKE_INSTALL_PREFIX=~/install/location
```

Run benchmarks using `nodejs`, e.g.,
```
nodejs bin/benchmark/lib-benchmark.js
```

## Running automatically converted C++ examples

Compile OpenFHE in the `embuild` directory using the following CMake flags
```
emcmake cmake .. -DBUILD_EXAMPLES=ON -DCMAKE_INSTALL_PREFIX=~/install/location
```

Run an exame using `nodejs`, e.g.,
```
nodejs bin/examples/pke/simple-integers
```

## Building OpenFHE-WASM

1. Clone the `openfhe-wasm` repository and cd into it

2. Run the following commands to build the NodeJS bindings.

```
mkdir build
cd build
emcmake cmake .. -DOpenFHE_DIR=${PREFIX}/lib/OpenFHE
emmake make
```

This should install emscripten libraries in `openfhe-wasm/lib` directory.

Now run the examples in the following directories using `nodejs`

* `examples/js/pke/`

## Running OpenFHE-WASM Examples

`OpenFHE-WASM` comes with the following examples, which are the JS versions of selected C++ PALISADE examples:

- [pre_buffer.js](examples/js/pke/pre-buffer.js): demonstrates use of OpenFHE for encryption, proxy re-encryption and decryption of packed vector of binary data
- [simple_integer.js](examples/js/pke/simple_integer.js): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFV
- [simple_integer_bgvrns.js](examples/js/pke/simple_integer_bgvrns.js): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGV
- [simple_integer_serialization.js](examples/js/pke/simple_integer_serialization.js): simple example with serialization showing homomorphic additions, multiplications, and rotations for vectors of integers using BFV
- [simple_real_number.js](examples/js/pke/simple_real_number.js): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [threshold_fhe_bfv.js](examples/js/pke/threshold_fhe_bfv.js): example of threshold BFV

# Notes specific to OpenFHE WebAssembly

* We have managed to compile `OpenFHE-WASM` using emscripten 3.1.30 through 4.0.8. A more recent version of `nodejs` (20 or later) should be used to achieve the best performance.
* The `OpenFHE-WASM` port is somewhat slower (typically 1.5 to 3.x depending on the operation) than the native C++ version of OpenFHE (in g++ or clang++) due to a normal slowdown incurred in web assembly builds (typically 2x) and additional slow-down due to the use of 64-bit arithmetic in PALISADE (64-bit arithmetic is emulated in WASM).
* Web assembly running environment is typically limited to 4GB of RAM.
* `OpenFHE-WASM` does not currently support multi-threading.
