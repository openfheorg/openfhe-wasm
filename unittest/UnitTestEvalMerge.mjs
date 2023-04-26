import assert from 'assert'
import factory from '../lib/openfhe_pke.js'
import {copyVecToJs, setupParamsBFV, setupCCBFV} from "./common.mjs";

function mockEvalMerge(arrays) {
    return arrays.map(array => array[0])
}

async function TestArbBFVEvalMerge() {
    const module = await factory();

    let params = await new module.CCParamsCryptoContextBFVRNS();
    params = await setupParamsBFV(params);
    let cc = new module.GenCryptoContextBFV(params);
    let kp = undefined;
    [cc, kp] = await setupCCBFV(cc, [-1, -2, -3, -4, -5, -6, -7, -8])
    try {
        const arrays = [
            [4],
            [2],
            [3],
            [5],
        ];
        const expected = mockEvalMerge(arrays);
        const vectors = arrays.map(
            array => module.MakeVectorInt64Clipped(array)
        );
        // rotation keys MUST be pre-computed to use EvalMerge()
        const plaintexts = vectors.map(
            vector => cc.MakePackedPlaintext(vector)
        );

        const ciphertexts = plaintexts.map(
            plaintext => cc.Encrypt(kp.publicKey, plaintext)
        );

        const ciphertextProduct = cc.EvalMerge(ciphertexts);
        const plaintext = cc.Decrypt(kp.secretKey, ciphertextProduct);
        plaintext.SetLength(arrays.length);
        const got = copyVecToJs(plaintext.GetPackedValue());

        assert.deepEqual(expected, got);
    } catch (error) {
        const msg = typeof error === 'number' ?
            module.getExceptionMessage(error) : error
        throw new Error(msg)
    }
}

describe('CryptoContext', () => {
    describe('#EvalMerge()', () => {
        it('Should merge multiple ciphertexts into one', TestArbBFVEvalMerge)
            .timeout(10000)
    });
});
