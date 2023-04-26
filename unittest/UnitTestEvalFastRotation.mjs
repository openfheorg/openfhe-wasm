import assert from 'assert'
import factory from '../lib/openfhe_pke.js'
import {copyVecToJs, setupCCBGV, setupParamsBGV,} from "./common.mjs";

function rotate(x, index) {
    return x.slice(index).concat(x.slice(0, index));
}

function mockFastRotations(x, rotations) {
    return rotations.map(rotation => rotate(x, rotation))
}

async function TestFastRotationCorrect() {
    const module = await factory();
    const x = [0, 0, 0, 0, 0, 0, 0, 1];
    const rotations = [1, 2, 3, 4, 5, 6, 7];

    let params = await new module.CCParamsCryptoContextBGVRNS();
    params = await setupParamsBGV(params);
    let cc = new module.GenCryptoContextBGV(params);
    let kp = undefined;
    [cc, kp] = await setupCCBGV(cc, rotations);
    try {

        const expected = mockFastRotations(x, rotations);
        const vector = module.MakeVectorInt64Clipped(x);

        const plaintext = cc.MakePackedPlaintext(vector);

        const ciphertext = cc.Encrypt(kp.publicKey, plaintext);

        // M is the cyclotomic order and we need it to call EvalFastRotation()
        const M = 2 * cc.GetRingDimension();

        // need to generate eval keys for each of the rotations we are doing
        // pre-computation is required to use EvalFastRotation()
        const precomp = cc.EvalFastRotationPrecompute(ciphertext);
        const rotatedCiphertexts = rotations.map(
            rotation => cc.EvalFastRotation(ciphertext, rotation, M, precomp)
        );

        const decryptedPlaintexts = rotatedCiphertexts.map(
            ciphertext => cc.Decrypt(kp.secretKey, ciphertext)
        );
        decryptedPlaintexts.forEach(plaintext => plaintext.SetLength(x.length));
        const got = decryptedPlaintexts.map(
            plaintext => copyVecToJs(plaintext.GetPackedValue())
        );

        assert.deepEqual(expected, got);
    } catch (error) {
        throw typeof error === 'number' ?
            new Error(module.getExceptionMessage(error)) : error
    }
}

describe('CryptoContext', () => {
    describe('#EvalFastRotation()', () => {
        it('Should rotate ciphertexts correctly', TestFastRotationCorrect)
            .timeout(20000)
    });
});
