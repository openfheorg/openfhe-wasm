// We combine both the JSON and binary serialization into one script. Seems silly to have multiple implementations
// when they are both basically the same

async function runner(sertype){

    const factory = require('../../../lib/openfhe_pke')
    const module = await factory();
    // Sample Program: Step 1: Set CryptoContext
    console.info("Setting up the Cryptocontext")

    let params = new module.CCParamsCryptoContextBFVRNS();
    params.SetPlaintextModulus(65537);
    params.SetMultiplicativeDepth(2);
    params.SetSecurityLevel(module.SecurityLevel.HEStd_128_classic);
    let cryptoContext = new module.GenCryptoContextBFV(params);

    // Enable features that you wish to use
    cryptoContext.Enable(module.PKESchemeFeature.PKE);
    cryptoContext.Enable(module.PKESchemeFeature.ADVANCEDSHE);
    cryptoContext.Enable(module.PKESchemeFeature.LEVELEDSHE);

    console.log("The cryptocontext has been generated.");

    // Serialize cryptocontext
    const cryptoContextBuffer =
        module.SerializeCryptoContextToBuffer(cryptoContext, sertype);
    console.log("The cryptocontext has been serialized");
    console.log(cryptoContextBuffer)

    // Deserialize the cryptocontext
    //
    // NOTE: should we match CPP and call this
    // module.Serial.DeserializeFromFile
    // or would that be too verbose???
    const cc = module.DeserializeCryptoContextFromBuffer(
        cryptoContextBuffer, sertype);

    console.log("The cryptocontext has been deserialized");

    // Sample Program: Step 2: Key Generation

    console.info("Key Generation")
    // Generate a public/private key pair

    const keyPair = cc.KeyGen();
    console.log("The key pair has been generated");

    // Serialize the public key
    const publicKeyBuffer =
        module.SerializePublicKeyToBuffer(keyPair.publicKey, sertype);
    console.log("The public key has been serialized");

    // Serialize the private key
    const privateKeyBuffer =
        module.SerializePrivateKeyToBuffer(keyPair.secretKey, sertype);
    console.log("The secret key has been serialized");

    // Generate the relinearization key
    cc.EvalMultKeyGen(keyPair.secretKey);

    console.log("The eval mult keys have been generated");

    // Serialize the relinearization (evaluation) key
    // for homomorphic multiplication
    const evalMultKeyBuffer =
        cc.SerializeEvalMultKeyToBuffer(sertype);
    console.log("The eval mult keys have been serialized");

    // Generate the rotation evaluation keys
    cc.EvalAtIndexKeyGen(keyPair.secretKey, [1, 2, -1, -2]);

    console.log("The rotation keys have been generated");

    // Serialize the rotation keys
    const automorphismKeyBuffer =
        cc.SerializeEvalAutomorphismKeyToBuffer(sertype);
    console.log("The eval rotation keys have been serialized");

    // Generate the summation evaluation keys
    cc.EvalSumKeyGen(keyPair.secretKey);

    console.log("The summation keys have been generated");

    // Serialize the summation keys
    const sumKeyBuffer =
        cc.SerializeEvalSumKeyToBuffer(sertype);
    console.log("The eval summation keys have been serialized");

    // Sample Program: Step 3: Encryption
    console.info("Encryption Step")
    // First plaintext vector is encoded
    const vectorOfInts1 =
        module.MakeVectorInt64Clipped([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const plaintext1 = cc.MakePackedPlaintext(vectorOfInts1, 1, 0);
    // Second plaintext vector is encoded
    const vectorOfInts2 =
        module.MakeVectorInt64Clipped([3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const plaintext2 = cc.MakePackedPlaintext(vectorOfInts2, 1, 0);
    // Third plaintext vector is encoded
    const vectorOfInts3 =
        module.MakeVectorInt64Clipped([1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12]);
    const plaintext3 = cc.MakePackedPlaintext(vectorOfInts3, 1, 0);

    console.log(`Plaintext #1: ${plaintext1}`)
    console.log(`Plaintext #2: ${plaintext2}`)
    console.log(`Plaintext #3: ${plaintext3}`)

    const pk = module.DeserializePublicKeyFromBuffer(publicKeyBuffer, sertype);

    console.log("The public key has been deserialized");

    // The encoded vectors are encrypted
    const ciphertext1 = cc.Encrypt(pk, plaintext1);
    const ciphertext2 = cc.Encrypt(pk, plaintext2);
    const ciphertext3 = cc.Encrypt(pk, plaintext3);

    console.log("The plaintexts have been encrypted");

    const ciphertext1Buffer =
        module.SerializeCiphertextToBuffer(ciphertext1, sertype);
    console.log("The first ciphertext has been serialized.");

    const ct1 =
        module.DeserializeCiphertextFromBuffer(ciphertext1Buffer, sertype);
    console.log("The first ciphertext has been deserialized");

    // Sample Program: Step 4: Evaluation
    console.info("Clearing keys and releasing contexts")

    cc.ClearEvalMultKeys();
    cc.ClearEvalAutomorphismKeys();
    cc.ClearEvalSumKeys();
    console.info("Deserializing all previously-serialized data")

    cc.DeserializeEvalMultKeyFromBuffer(evalMultKeyBuffer, sertype);
    console.log("Deserialized the eval mult keys");

    cc.DeserializeEvalAutomorphismKeyFromBuffer(
        automorphismKeyBuffer, sertype);
    console.log("Deserialized the eval rotation keys");

    cc.DeserializeEvalSumKeyFromBuffer(
        sumKeyBuffer, sertype);
    console.log("Deserialized the eval summation keys");

    // Homomorphic additions
    const ciphertextAdd12 = cc.EvalAddCipherCipher(ct1, ciphertext2);
    const ciphertextAddResult = cc.EvalAddCipherCipher(ciphertextAdd12, ciphertext3);

    // Homomorphic multiplications
    const ciphertextMul12 = cc.EvalMultCipherCipher(ct1, ciphertext2);
    const ciphertextMultResult = cc.EvalMultCipherCipher(ciphertextMul12, ciphertext3);

    // Homomorphic rotations
    const ciphertextRot1 = cc.EvalAtIndex(ct1, 1);
    const ciphertextRot2 = cc.EvalAtIndex(ct1, 2);
    const ciphertextRot3 = cc.EvalAtIndex(ct1, -1);
    const ciphertextRot4 = cc.EvalAtIndex(ct1, -2);

    // Homomorphic summation
    const ciphertextSum = cc.EvalSum(ct1, cc.GetBatchSize());

    // Sample Program: Step 5: Decryption
    const sk = module.DeserializePrivateKeyFromBuffer(
        privateKeyBuffer, sertype);
    console.log("The secret key has been deserialized");

    // Decrypt the result of additions
    const plaintextAddResult = cc.Decrypt(sk, ciphertextAddResult);
    // Decrypt the result of multiplications
    const plaintextMultResult = cc.Decrypt(sk, ciphertextMultResult);
    // Decrypt the result of rotations
    const plaintextRot1 = cc.Decrypt(sk, ciphertextRot1);
    const plaintextRot2 = cc.Decrypt(sk, ciphertextRot2);
    const plaintextRot3 = cc.Decrypt(sk, ciphertextRot3);
    const plaintextRot4 = cc.Decrypt(sk, ciphertextRot4);

    // Show only the same number of elements
    // as in the original plaintext vector.
    // By default it will show all coefficients
    // in the BFV_encoded polynomial.
    plaintextRot1.SetLength(vectorOfInts1.size());
    plaintextRot2.SetLength(vectorOfInts1.size());
    plaintextRot3.SetLength(vectorOfInts1.size());
    plaintextRot4.SetLength(vectorOfInts1.size());

    // Decrypt the result of sumation
    const plaintextSum = cc.Decrypt(sk, ciphertextSum);
    plaintextSum.SetLength(vectorOfInts1.size());

    // Output results
    console.log("\nResults of homomorphic computations");
    console.log(`#1 + #2 + #3: ${plaintextAddResult}`);
    console.log(`#1 * #2 * #3: ${plaintextMultResult}`);
    console.log(`Left rotation of #1 by 1: ${plaintextRot1}`);
    console.log(`Left rotation of #1 by 2: ${plaintextRot2}`);
    console.log(`Right rotation of #1 by 1: ${plaintextRot3}`);
    console.log(`Right rotation of #1 by 2: ${plaintextRot4}`);
    console.log(`Summation of all elements in #1: ${plaintextSum}`);

    return 0;
}

async function main() {

    const factory = require('../../../lib/openfhe_pke')
    const module = await factory();
    await runner(module.SerType.BINARY);
    console.info("\n**************************************************************************************************\n");
    console.info("Binary serialization test complete. Running Json serialization tests");
    module.ReleaseAllContexts();
    await runner(module.SerType.JSON);
    console.info("All serialization tests complete!");

}

main().then(exitCode => console.log(exitCode));

