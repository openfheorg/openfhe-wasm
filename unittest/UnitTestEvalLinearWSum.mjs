import assert from 'assert'
import factory from '../lib/openfhe_pke.js'
import {copyVecToJs, setupCCBGV, setupCCCKKS, setupParamsBGV, setupParamsCKKS,} from "./common.mjs";

function makeRandomArray(size, limit) {
    return [...Array(size)]
        .map(() => Math.round(Math.random() * limit))
}

function makeRandomArrays(size, limit, count) {
    return [...Array(count)].map(() => makeRandomArray(size, limit));
}

function dot(x, y) {
    let sum = 0;
    for (let i = 0; i < x.length; ++i) {
        sum += x[i] * y[i];
    }
    return sum;
}

function mockLinearWSum(x, weights) {
    const result = Array(x[0].length).fill(0);
    for (let i = 0; i < result.length; ++i) {
        const col = x.map(row => row[i]);
        result[i] = dot(col, weights);
    }
    return result;
}

const size = 4;
const count = 3;
const limit = 15;

async function TestLinearWSumCorrect() {

    const x = makeRandomArrays(size, limit, count);
    const weights = makeRandomArray(count, limit);

    const module = await factory();
    let result = null;
    try {
        result = await LinearWSum(module, x, weights);
    } catch (error) {
        if (typeof error === 'number')
            throw new Error(module.getExceptionMessage(error))
        else
            throw error
    }
    const expectedResult = mockLinearWSum(x, weights);

    assert.deepEqual(expectedResult, result);
}

async function LinearWSum(module, x, weights) {
    let params = await new module.CCParamsCryptoContextCKKSRNS();
    params = await setupParamsBGV(params);
    let cc = new module.GenCryptoContextCKKS(params);
    let kp = undefined;
    [cc, kp] = await setupCCCKKS(cc, []);

    const vecs = x.map(
        array => new module.VectorDouble(array)
    );
    const plaintexts = vecs.map(
        vec => cc.MakeCKKSPackedPlaintext(vec)
    );

    cc.EvalSumKeyGen(kp.secretKey);
    cc.EvalMultKeyGen(kp.secretKey);

    const ciphertexts = plaintexts.map(
        plaintext => cc.Encrypt(kp.publicKey, plaintext)
    );

    const result = cc.EvalLinearWSum(ciphertexts, weights);

    const decrypted = cc.Decrypt(kp.secretKey, result);
    decrypted.SetLength(x[0].length);
    const rawResult = copyVecToJs(decrypted.GetRealPackedValue());
    return rawResult.map(x => Math.round(x));
}

describe('CryptoContext', () => {
    describe("#EvalLinearWSum()", () => {
        it(
            'Should compute the same weighted sum ' +
            'for ciphertexts as native numbers',
            TestLinearWSumCorrect
        ).timeout(20000) // increase timeout because operation is slow
    });
});
