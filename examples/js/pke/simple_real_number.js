function getVectorDouble(arr) {
    let vec = new module.VectorDouble();
    for (let i of arr) vec.push_back(i);
    return vec;
}

async function main() {
    const factory = require('../../../lib/openfhe_pke')
    const module = await factory()
    // Set the main parameters
    // all int types are number in typescript unless defined otherwise.
    // Step 1: Setup CryptoContext
    const multDepth = 1;
    const scalingModSize = 50;
    const batchSize = 8;
    const securityLevel = module.SecurityLevel.HEStd_128_classic;
    let params = new module.CCParamsCryptoContextCKKSRNS();

    params.SetMultiplicativeDepth(multDepth);
    params.SetSecurityLevel(securityLevel);
    parames.SetScalingModSize(scalingModSize);
    parames.SetBatchSize(batchSize);
    console.log(`Mult Depth was: ${params.GetMultiplicativeDepth()}`);
    let cc = new module.GenCryptoContextCKKS(params);

    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.KEYSWITCH);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);



    console.log(`CKKS scheme is using ring dimension ${cc.GetRingDimension()}\n`)

    cc.Enable(module.PKESchemeFeature.ENCRYPTION);
    cc.Enable(module.PKESchemeFeature.SHE);

    // Step 2: Key Generation
    const keys = cc.KeyGen();
    cc.EvalMultKeyGen(keys.secretKey);
    cc.EvalAtIndexKeyGen(keys.secretKey, [1, -2]);

    // Step 3: Encoding and encryption of targets
    const x1 = new module.VectorDouble([0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]);
    const x2 = new module.VectorDouble([5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]);

    const ptxt1 = cc.MakeCKKSPackedPlaintext(x1);
    const ptxt2 = cc.MakeCKKSPackedPlaintext(x2);

    console.log(`Input x1: ${ptxt1}`);
    console.log(`Input x2: ${ptxt2}`);

    const c1 = cc.Encrypt(keys.publicKey, ptxt1);
    const c2 = cc.Encrypt(keys.publicKey, ptxt2);

    // Step 4: Evaluation
    // note that overloads hve been replaced with separate methods here
    const cAdd = cc.EvalAddCipherCipher(c1, c2);
    const cSub = cc.EvalSubCipherCipher(c1, c2);
    const cScalar = cc.EvalMultCipherConstant(c1, 4.0);
    const cMul = cc.EvalMultCipherCipher(c1, c2);

    const cRot1 = cc.EvalAtIndex(c1, 1);
    const cRot2 = cc.EvalAtIndex(c1, -2);

    // Step 5: Decryption and output
    let result;
    console.log('Results of homomorphic computations');
    result = cc.Decrypt(keys.secretKey, cAdd);
    result.SetLength(batchSize);
    console.log(`x1 + x2 = ${result} Estimated precision in bits ${result.GetLogPrecision()}`)

    result = cc.Decrypt(keys.secretKey, cSub);
    result.SetLength(batchSize);
    console.log(`x1 - x2 = ${result}`);

    result = cc.Decrypt(keys.secretKey, cScalar);
    result.SetLength(batchSize);
    console.log(`4 * x1 = ${result}`);

    result = cc.Decrypt(keys.secretKey, cMul);
    result.SetLength(batchSize);
    console.log(`x1 * x2 = ${result}`);

    result = cc.Decrypt(keys.secretKey, cRot1);
    result.SetLength(batchSize);
    console.log('\nIn rotations, very small outputs (~10^-10 here) correspond to 0\'s:\n')
    console.log(`x1 rotate by 1 = ${result}`)

    result = cc.Decrypt(keys.secretKey, cRot2);
    result.SetLength(batchSize);
    console.log(`x1 rotate by -2 = ${result}`)

    return 0;
}

main().then(exitCode => console.log(exitCode));


async function main() {

    let keyPair = cc.KeyGen();
    cc.EvalMultKeyGen(keyPair.secretKey);
    cc.EvalAtIndexKeyGen(keyPair.secretKey, [1, 2, -1, -2]);

    console.log(cc);
    const vectorOfInts1 = module.MakeVectorInt64Clipped(
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    //"Plaintext" type is switched to string
    const plaintext1 = cc.MakePackedPlaintext(vectorOfInts1, 1, 0);
    // Second plaintext vector is encoded (64bit signed in C/C++ => BigInt64Array
    // in JS)
    const vectorOfInts2 = module.MakeVectorInt64Clipped(
        [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    //"Plaintext" type is switched to string
    getMethods(cc);
    const plaintext2 = cc.MakePackedPlaintext(vectorOfInts2, 1, 0);
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
