import assert from 'assert'
import factory from '../lib/openfhe_pke.js'
import {copyVecToJs, } from "./common.mjs";

const targetTowers = 1;

async function TestBGVCompress(){
    const module = await factory();
    /** Set the main parameters
     * all int types are number in typescript unless defined otherwise.
     */

    const plaintextMod = 65537;
    const multDepth = 2;
    const sDev = 3.2
    let params = new module.CCParamsCryptoContextBGVRNS();
    params.SetPlaintextModulus(plaintextMod);
    params.SetMultiplicativeDepth(multDepth);
    params.SetStandardDeviation(sDev);
    params.SetSecurityLevel(module.SecurityLevel.HEStd_128_classic);
    params.SetSecretKeyDist(module.SecretKeyDist.UNIFORM_TERNARY);
    params.SetKeySwitchTechnique(module.KeySwitchTechnique.HYBRID);


    let cc = new module.GenCryptoContextBGV(params);
    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.PRE);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);

    let kp = cc.KeyGen();
    cc.EvalMultKeyGen(kp.secretKey);
    cc.EvalAtIndexKeyGen(kp.secretKey, [1, 2, -1, -2]);
    try {

        const x = [5];
        // operation is squaring; expect x^2
        const expected = x[0] * x[0];
        const vector = module.MakeVectorInt64Clipped(x);
        const plaintext = cc.MakePackedPlaintext(vector);

        const ciphertext = cc.Encrypt(kp.publicKey, plaintext);
        // perform multiplication to increase towers
        const ciphertextSquared =
            cc.EvalMultCipherCipher(ciphertext, ciphertext);

        // in the JS port, we don't bother exporting ciphertext.GetElements().
        // Instead, verify compression works by asserting that
        // the serialized compressed ciphertext is smaller than
        // the serialized original ciphertext.
        const compressed = cc.Compress(ciphertextSquared, targetTowers);

        const originalBuffer =
            module.SerializeCiphertextToBuffer(ciphertextSquared, module.SerType.BINARY);
        const compressedBuffer =
            module.SerializeCiphertextToBuffer(compressed, module.SerType.BINARY);

        const originalBufferLength = originalBuffer.byteLength;
        const compressedBufferLength = compressedBuffer.byteLength;

        assert(compressedBufferLength < originalBufferLength);

        const decrypted = cc.Decrypt(kp.secretKey, ciphertextSquared);
        const got = decrypted.GetPackedValue().get(0);

        assert.equal(expected, got);
    } catch (error) {
        const msg = typeof error === 'number' ?
            module.getExceptionMessage(error) : error
        throw new Error(msg)
    }

}

describe('CryptoContext', () => {
    describe('#Compress()', () => {
        it('Should reduce tower size to specified target', TestBGVCompress)
            .timeout(10000)
    });
});
