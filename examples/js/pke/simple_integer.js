async function main() {
    const factory = require('../../../lib/openfhe_pke')
    const module = await factory()
    // Set the main parameters
    // all int types are number in typescript unless defined otherwise.
    const plaintextMod = 65537;
    const multDepth = 2;
    params = new module.CCParamsCryptoContextBFVRNS();
    params.SetWrappedPlaintextModulus(plaintextMod);
    console.log(`Plaintext Modulus was: ${params.GetWrappedPlaintextModulus()}`);

    params.SetWrappedMultiplicativeDepth(multDepth);
    console.log(`Mult Depth was: ${params.GetWrappedMultiplicativeDepth()}`);
    // params.SetMultDepth(multDepth);
    // params = new module.CCParamsBGV();
    // cc = module.GenCryptoContextBFV2();
    // cc.Enable(module.PKESchemeFeature.PKE);

    // for (let methodIdx = 0; methodIdx < 2; methodIdx++) {
    //     if (methodIdx === 0) {
    //         cryptoContext = new module.GenCryptoContextBFVrns(
    //             plaintextModulus, module.SecurityLevel.HEStd_128_classic, sigma, 0, depth, 0, module.MODE.OPTIMIZED);
    //     } else {
    //
    //         cryptoContext = new module.ParamGenBFVrns(
    //             0, plaintextModulus, module.SecurityLevel.HEStd_128_classic, sigma, depth, module.MODE.OPTIMIZED,
    //             2, 0, 60, 0
    //         );
    //     }
    //
    //     // Enable features that you wish to use
    //     // from  core/include/utils/inttype.h, line 115
    //     cryptoContext.Enable(module.PKESchemeFeature.ENCRYPTION);
    //     cryptoContext.Enable(module.PKESchemeFeature.SHE);
    //     // Initialize Public Key Containers
    //     // Define LPKeyPair<DCRTPoly> type then replace "any" type below
    //     // Generate a public/private key pair
    //     let keyPair = cryptoContext.KeyGen();
    //     // Generate the relinearization key
    //     cryptoContext.EvalMultKeyGen(keyPair.secretKey);
    //     // Generate the rotation evaluation keys
    //     cryptoContext.EvalAtIndexKeyGen(keyPair.secretKey, [1, 2, -1, -2]);
    //     // Sample Program: Step 3: Encryption
    //     // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays
    //     // First plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
    //     // in JS)
    //     const vectorOfInts1 = module.MakeVectorInt64Clipped(
    //         [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    //     //"Plaintext" type is switched to string
    //     const plaintext1 = cryptoContext.MakePackedPlaintext(vectorOfInts1);
    //     // Second plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
    //     // in JS)
    //     const vectorOfInts2 = module.MakeVectorInt64Clipped(
    //         [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    //     //"Plaintext" type is switched to string
    //     const plaintext2 = cryptoContext.MakePackedPlaintext(vectorOfInts2);
    //     // Third plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
    //     // in JS)
    //     const vectorOfInts3 = module.MakeVectorInt64Clipped(
    //         [1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]);
    //     //"Plaintext" type is switched to string
    //     const plaintext3 = cryptoContext.MakePackedPlaintext(vectorOfInts3);
    //     // The encoded vectors are encrypted
    //     const ciphertext1 = cryptoContext.Encrypt(keyPair.publicKey, plaintext1);
    //     const ciphertext2 = cryptoContext.Encrypt(keyPair.publicKey, plaintext2);
    //     const ciphertext3 = cryptoContext.Encrypt(keyPair.publicKey, plaintext3);
    //     // Sample Program: Step 4: Evaluation
    //     // all "auto" types become "any"
    //     // Homomorphic additions
    //     const ciphertextAdd12 = cryptoContext.EvalAddCipherCipher(ciphertext1, ciphertext2);
    //     const ciphertextAddResult = cryptoContext.EvalAddCipherCipher(ciphertextAdd12, ciphertext3);
    //     // Homomorphic multiplications
    //     const ciphertextMul12 = cryptoContext.EvalMultCipherCipher(ciphertext1, ciphertext2);
    //     const ciphertextMultResult = cryptoContext.EvalMultCipherCipher(ciphertextMul12, ciphertext3);
    //     const ciphertextMultCtPt = cryptoContext.EvalMultCipherPlaintext(ciphertext1, plaintext1);
    //     // Homomorphic rotations
    //     const ciphertextRot1 = cryptoContext.EvalAtIndex(ciphertext1, 1);
    //     const ciphertextRot2 = cryptoContext.EvalAtIndex(ciphertext1, 2);
    //     const ciphertextRot3 = cryptoContext.EvalAtIndex(ciphertext1, -1);
    //     const ciphertextRot4 = cryptoContext.EvalAtIndex(ciphertext1, -2);
    //     // Sample Program: Step 5: Decryption
    //     // Decrypt the result of additions
    //     // Plaintext => any
    //     let plaintextAddResult = cryptoContext.Decrypt(keyPair.secretKey, ciphertextAddResult);
    //     // Decrypt the result of multiplications
    //     // Plaintext => any
    //     let plaintextMultResult = cryptoContext.Decrypt(keyPair.secretKey, ciphertextMultResult);
    //     // Decrypt the result of rotations
    //     //"Plaintext" => "implicit, emscripten will handle"
    //     let plaintextRot1 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot1);
    //     let plaintextRot2 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot2);
    //     let plaintextRot3 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot3);
    //     let plaintextRot4 = cryptoContext.Decrypt(keyPair.secretKey, ciphertextRot4);
    //     let plaintextMultCtPt = cryptoContext.Decrypt(keyPair.secretKey, ciphertextMultCtPt);
    //
    //     plaintextRot1.SetLength(vectorOfInts1.size());
    //     plaintextRot2.SetLength(vectorOfInts1.size());
    //     plaintextRot3.SetLength(vectorOfInts1.size());
    //     plaintextRot4.SetLength(vectorOfInts1.size());
    //     plaintextMultCtPt.SetLength(vectorOfInts1.size());
    //
    //     console.log(`Plaintext #1: ${plaintext1}`);
    //     console.log(`Plaintext #2: ${plaintext2}`);
    //     console.log(`Plaintext #3: ${plaintext3}`);
    //     // Output results
    //     console.log('\nResults of homomorphic computations');
    //     console.log(`#1 + #2 + #3: ${plaintextAddResult}`);
    //     console.log(`#1 * #2 * #3: ${plaintextMultResult}`);
    //     console.log(`Left rotation of #1 by 1: ${plaintextRot1}`);
    //     console.log(`Left rotation of #1 by 2: ${plaintextRot2}`);
    //     console.log(`Right rotation of #1 by 1: ${plaintextRot3}`);
    //     console.log(`Right rotation of #1 by 2: ${plaintextRot4}`);
    //     console.log(`Ciphertext-Plaintext Multiplication #1 * #1: ${plaintextMultCtPt}`)
    //     console.log("\n");
    //     cryptoContext.delete();
    // }
    return 0;
}

main().then(exitCode => {
    if (exitCode === 0){
        console.log(`\x1b[32m`, "Finished successfully", `\x1b[0m`);
    } else {
        console.log(`\x1b[31m`, "Finished successfully", `\x1b[0m`);
    }
});
