function getMethods(obj) {
    var result = [];
    for (var id in obj) {
        try {
            if (typeof (obj[id]) == "function") {
                result.push(id + ": " + obj[id].toString());
            }
        } catch (err) {
            result.push(id + ": inaccessible");
        }
    }
    return result;
}

async function main() {
    const factory = require('../../../lib/openfhe_pke')
    const module = await factory()
    // Set the main parameters
    // all int types are number in typescript unless defined otherwise.
    const plaintextMod = 65537;
    const multDepth = 2;
    let params = new module.CCParamsCryptoContextBFVRNS();
    params.SetPlaintextModulus(plaintextMod);
    console.log(`Plaintext Modulus was: ${params.GetPlaintextModulus()}`);

    params.SetMultiplicativeDepth(multDepth);
    console.log(`Mult Depth was: ${params.GetMultiplicativeDepth()}`);
    let cc = new module.GenCryptoContextBFV(params);

    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.PRE);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);

    let keyPair = cc.KeyGen();
    cc.EvalMultKeyGen(keyPair.secretKey);
    cc.EvalAtIndexKeyGen(keyPair.secretKey, [1, 2, -1, -2]);

    console.log(cc);
    const in1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    const vectorOfInts1 = module.MakeVectorInt64Clipped(in1);
    //"Plaintext" type is switched to string
    const plaintext1 = cc.MakePackedPlaintext(vectorOfInts1, 1);
    // Second plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
    // in JS)
    const vectorOfInts2 = module.MakeVectorInt64Clipped(
        [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    //"Plaintext" type is switched to string
    getMethods(cc);
    const plaintext2 = cc.MakePackedPlaintext(vectorOfInts2);
    // Third plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
    // in JS)
    const vectorOfInts3 = module.MakeVectorInt64Clipped(
        [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]);
    //"Plaintext" type is switched to string
    const plaintext3 = cc.MakePackedPlaintext(vectorOfInts3, 1, 0);
    // The encoded vectors are encrypted
    const ciphertext1 = cc.Encrypt(keyPair.publicKey, plaintext1);
    const ciphertext2 = cc.Encrypt(keyPair.publicKey, plaintext2);
    const ciphertext3 = cc.Encrypt(keyPair.publicKey, plaintext3);
    // Sample Program: Step 4: Evaluation
    // all "auto" types become "any"
    // Homomorphic additions
    const ciphertextAdd12 = cc.EvalAddCipherCipher(ciphertext1, ciphertext2);
    const ciphertextAddResult = cc.EvalAddCipherCipher(ciphertextAdd12, ciphertext3);
    // Homomorphic multiplications
    const ciphertextMul12 = cc.EvalMultCipherCipher(ciphertext1, ciphertext2);
    const ciphertextMultResult = cc.EvalMultCipherCipher(ciphertextMul12, ciphertext3);
    const ciphertextMultCtPt = cc.EvalMultCipherPlaintext(ciphertext1, plaintext1);
    // Homomorphic rotations
    const ciphertextRot1 = cc.EvalAtIndex(ciphertext1, 1);
    const ciphertextRot2 = cc.EvalAtIndex(ciphertext1, 2);
    const ciphertextRot3 = cc.EvalAtIndex(ciphertext1, -1);
    const ciphertextRot4 = cc.EvalAtIndex(ciphertext1, -2);
    // Sample Program: Step 5: Decryption
    // Decrypt the result of additions
    // Plaintext => any
    let plaintextAddResult = cc.Decrypt(keyPair.secretKey, ciphertextAddResult);
    // Decrypt the result of multiplications
    // Plaintext => any
    let plaintextMultResult = cc.Decrypt(keyPair.secretKey, ciphertextMultResult);
    // Decrypt the result of rotations
    //"Plaintext" => "implicit, emscripten will handle"
    let plaintextRot1 = cc.Decrypt(keyPair.secretKey, ciphertextRot1);
    let plaintextRot2 = cc.Decrypt(keyPair.secretKey, ciphertextRot2);
    let plaintextRot3 = cc.Decrypt(keyPair.secretKey, ciphertextRot3);
    let plaintextRot4 = cc.Decrypt(keyPair.secretKey, ciphertextRot4);
    let plaintextMultCtPt = cc.Decrypt(keyPair.secretKey, ciphertextMultCtPt);

    plaintextRot1.SetLength(vectorOfInts1.size());
    plaintextRot2.SetLength(vectorOfInts1.size());
    plaintextRot3.SetLength(vectorOfInts1.size());
    plaintextRot4.SetLength(vectorOfInts1.size());
    plaintextMultCtPt.SetLength(vectorOfInts1.size());

    console.log(`Plaintext #1: ${plaintext1}`);
    console.log(`Plaintext #2: ${plaintext2}`);
    console.log(`Plaintext #3: ${plaintext3}`);
    // Output results
    console.log('\nResults of homomorphic computations');
    console.log(`#1 + #2 + #3: ${plaintextAddResult}`);
    console.log(`#1 * #2 * #3: ${plaintextMultResult}`);
    console.log(`Left rotation of #1 by 1: ${plaintextRot1}`);
    console.log(`Left rotation of #1 by 2: ${plaintextRot2}`);
    console.log(`Right rotation of #1 by 1: ${plaintextRot3}`);
    console.log(`Right rotation of #1 by 2: ${plaintextRot4}`);
    console.log(`Ciphertext-Plaintext Multiplication #1 * #1: ${plaintextMultCtPt}`)
    console.log("\n");
    cc.delete();

    return 0;
}

main().then(exitCode => {
    if (exitCode === 0) {
        console.log(`\x1b[32m`, "Finished successfully", `\x1b[0m`);
    } else {
        console.log(`\x1b[31m`, "Finished successfully", `\x1b[0m`);
    }
});
