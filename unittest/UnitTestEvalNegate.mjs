import assert from 'assert'
import factory from '../lib/openfhe_pke.js'
import {copyVecToJs, setupCCBFV, setupParamsBFV,} from "./common.mjs";

function mockEvalNegate(x) {
    return -x
}

async function TestArbBGVEvalNegate() {
    const module = await factory();

    let params = await new module.CCParamsCryptoContextBFVRNS();
    params = await setupParamsBFV(params);
    let cc = new module.GenCryptoContextBFV(params);
    let kp = undefined;
    [cc, kp] = await setupCCBFV(cc, [1, 2])

    try {

        const x = 5;
        const expected = mockEvalNegate(x);
        const vector = module.MakeVectorInt64Clipped([x]);

        const plaintext = cc.MakePackedPlaintext(vector);

        const ciphertext = cc.Encrypt(kp.publicKey, plaintext);

        const ciphertextNegated = cc.EvalNegate(ciphertext);
        const decrypted = cc.Decrypt(kp.secretKey, ciphertextNegated);
        const got = decrypted.GetPackedValue().get(0);

        assert.equal(expected, got);
    } catch (error) {
        const msg = typeof error === 'number' ?
            module.getExceptionMessage(error) : error
        throw new Error(msg)
    }
}

describe('CryptoContext', () => {
    describe('#EvalNegate()', () => {
        it('Should multiply ciphertext by -1', TestArbBGVEvalNegate)
            .timeout(10000)
    });
});

