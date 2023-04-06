# OpenFHE-WASM
WASM Port of OPENFHE Wasm

# Table of Contents
- [Installing OpenFHE-WASM](#build-instructions)
  - [TODO: Install from NPM](#from-npm)
  - [Building From Source](#building-from-source)
    - [Installing OpenFHE](#build-the-openfhe-library-with-emscripten)
    - [Installing OpenFHE-WASM](#building-openfhe-wasm)
  - [Running OpenFHE-WASM](#running-web-assembly-unit-tests) 
    - TODO
  - [Sharp Edges](#sharp-edges)

# General information

`openfhe-wasm` is the official web-assembly port of
the [OpenFHE homomorphic library](https://www.openfhe.org/). `openfhe-wasm` supports all homomorphic encryption
schemes supported by OpenFHE and exposes an API similar to the C++ API for OpenFHE.

`openfhe-wasm` is licensed under the BSD-3 license.

# Build instructions

## From NPM

@TODO: port and release after library finished

## Building from source

### Build the OpenFHE library with Emscripten

1. Install `emscripten` using the instructions at https://emscripten.org/docs/getting_started/downloads.html.
2. Install `NodeJs` if not already installed.
3. Clone [OpenFHE-development](https://github.com/openfheorg/openfhe-development) @TODO: once OpenFHE repo (stable version)

- **NOTE: As of 04/05/2023, only the `dev` branch works for the moment. If you see an issue about the math backend not being specified, make sure you're on the right branch**

4. `cd` into the cloned directory and create `embuild` directory.
5. Run

```
export PREFIX=~/install/location
mkdir embuild
cd embuild
emcmake cmake .. -DCMAKE_INSTALL_PREFIX=${PREFIX} -DMATHBACKEND=4
emmake make -jN
emmake make install
```

**Note**: 
- `N` is number of cores available on your system.
- `~/install/location` can be any empty directory location where openfhe binaries should be installed. 
- To include the unit tests, examples, or benchmarks, the corresponding cmake flags can be set to "ON" instead of "OFF".

### Building OpenFHE-WASM

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

# Sharp Edges 

Note that there have been a few notable differences from the original [PALISADE-WASM](https://gitlab.com/palisade/palisade-wasm/)

- `cc.MakePackedPlaintext` now requires the user to specify both the vector to pack, the depth, and the level. Previously only the first argument was necessary