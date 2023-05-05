// based on
// https://gitlab.com/palisade/palisade-development/-/blob/master/src/pke/unittest/UnitTestEvalInnerProduct.cpp

import assert from 'assert'
import factory from '../lib/openfhe_pke.js'
import {copyVecToJs, setupCCBFV, setupParamsBFV,} from "./common.mjs";

function makeRandomArray(size, limit) {
    return [...Array(size)]
        .map(() => Math.round(Math.random() * limit))
}

function dot(x, y) {
    let sum = 0;
    for (let i = 0; i < x.length; ++i) {
        sum += x[i] * y[i];
    }
    return sum;
}

async function TestArbBFVInnerProductPackedArray() {
    const input1 = [1,2,3,4,5];
    const expectedResult = dot(input1, input1);
    const result = await ArbBFVInnerProductPackedArray(input1, input1);

    assert.equal(expectedResult, result);
}

// both inputs are VectorInt64
async function ArbBFVInnerProductPackedArray(input1, input2) {

    const module = await factory();
    let params = await new module.CCParamsCryptoContextBFVRNS();
    params = await setupParamsBFV(params);
    let cc = new module.GenCryptoContextBFV(params);
    const size = cc.GetRingDimension();
    let kp = undefined;
    [cc, kp] = await setupCCBFV(cc);

    // Initialize the public key containers

    const input1vec = module.MakeVectorInt64Clipped(input1);
    const input2vec = module.MakeVectorInt64Clipped(input2);
    const intArray1 = cc.MakePackedPlaintext(input1vec);
    const intArray2 = cc.MakePackedPlaintext(input2vec);

    const ciphertext1 = cc.Encrypt(kp.publicKey, intArray1);
    const ciphertext2 = cc.Encrypt(kp.publicKey, intArray2);

    console.log("Evalling");
    const encResult = cc.EvalInnerProduct(ciphertext1, ciphertext2, size);
    let ptResult = cc.Decrypt(kp.secretKey, encResult);
    ptResult.SetLength(1);
    let result = ptResult.GetPackedValue();
    return result.get(0);
    //
    // const intArrayNew = cc.Decrypt(kp.secretKey, result);
    //
    // return intArrayNew.GetPackedValue().get(0);
    // return undefined;
}

describe('CryptoContext', () => {
    describe("#EvalInnerProduct()", () => {
        it(
            'Should compute the same inner product ' +
            'for ciphertexts as native numbers',
            TestArbBFVInnerProductPackedArray
        ).timeout(10000) // increase timeout because operation is slow
    });
});

