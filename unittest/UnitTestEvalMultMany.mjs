import assert from 'assert'
import factory from '../lib/openfhe_pke.js'
import {copyVecToJs, setupCCBFV, setupParamsBFV,} from "./common.mjs";

function mockEvalMultMany(arrays) {
    const result = Array(arrays[0].length).fill(1)
    for (let i = 0; i < arrays.length; i++) {
        for (let j = 0; j < result.length; j++) {
            result[j] *= arrays[i][j];
        }
    }
    return result;
}


async function TestArbBFVEvalMultMany() {
    const module = await factory();
    let params = await new module.CCParamsCryptoContextBFVRNS();
    params = await setupParamsBFV(params);
    let cc = new module.GenCryptoContextBFV(params);
    let kp = undefined;
    [cc, kp] = await setupCCBFV(cc)

    try {

        const arrays = [
            [2, 2, 3, 5, 7],
            [3, 2, 3, 5, 7],
            [5, 2, 3, 5, 7],
            [7, 2, 3, 5, 7],
        ];
        const expected = mockEvalMultMany(arrays);
        const vectors = arrays.map(
            array => module.MakeVectorInt64Clipped(array)
        );

        const plaintexts = vectors.map(
            vector => cc.MakePackedPlaintext(vector)
        );

        const ciphertexts = plaintexts.map(
            plaintext => cc.Encrypt(kp.publicKey, plaintext)
        );

        const ciphertextProduct = cc.EvalMultMany(ciphertexts);
        const plaintext = cc.Decrypt(kp.secretKey, ciphertextProduct);
        plaintext.SetLength(arrays[0].length);
        const got = copyVecToJs(plaintext.GetPackedValue());

        assert.deepEqual(expected, got);
    } catch (error) {
        const msg = typeof error === 'number' ?
            module.getExceptionMessage(error) : error
        throw new Error(msg)
    }
}

describe('CryptoContext', () => {
    describe('#EvalMultMany()', () => {
        it(
            'Should compute the same product ' +
            'for ciphertexts as native numbers',
            TestArbBFVEvalMultMany
        ).timeout(10000)
    });
});

