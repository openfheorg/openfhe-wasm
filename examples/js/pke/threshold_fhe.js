async function main() {
    const factory = require('../../../lib/openfhe_pke')
    const module = await factory();
    try {

        const init_size = 4;
        const scalingModSize = 50;
        const batchSize = 16;

        // Generate the cryptocontext

        let params = new module.CCParamsCryptoContextCKKSRNS();
        params.SetMultiplicativeDepth(init_size - 1);
        params.SetScalingModSize(scalingModSize);
        params.SetBatchSize(batchSize);
        params.SetSecurityLevel(module.SecurityLevel.HEStd_128_classic)
        params.SetRingDimension(0);
        params.SetScalingTechnique(module.ScalingTechnique.FIXEDMANUAL);
        params.SetKeySwitchTechnique(module.KeySwitchTechnique.BV);
        params.SetNumLargeDigits();



        const cc = module.GenCryptoContextCKKS(
            // init_size - 1,   // multiplicative depth
            // scalingModSize,     // Scaling Factor bits/dcrtbits / scaling mod size
            // batchSize,
            // module.SecurityLevel.HEStd_128_classic,
            // 0, // ringDimension
            module.RescalingTechnique.APPROXRESCALE,  // rescaling technique
            module.KeySwitchTechnique.BV,               // keyswitching technique
            2, // numLargeDigits
            2, // maxDepth
            60, // firstMod
            5,                                        // relinWindow
            module.MODE.OPTIMIZED
        );

        // Enable features that you wish to use
        cc.Enable(module.PKESchemeFeature.ENCRYPTION);
        cc.Enable(module.PKESchemeFeature.SHE);
        cc.Enable(module.PKESchemeFeature.LEVELEDSHE);
        cc.Enable(module.PKESchemeFeature.MULTIPARTY);

        ////////////////////////////////////////////////////////////
        // Set-up of parameters
        ////////////////////////////////////////////////////////////

        // Print out the parameters
        console.log(`p = ${cc.GetCryptoParameters().GetPlaintextModulus()}`)
        const n =
            cc.GetCryptoParameters().GetElementParams().GetCyclotomicOrder() / 2;
        console.log(`n = ${n}`)
        const log2q = Math.log2(
            cc.GetCryptoParameters().GetElementParams().GetModulus().ConvertToDouble()
        );
        console.log(`log2 q = ${log2q}`);

        ////////////////////////////////////////////////////////////
        // Perform Key Generation Operation
        ////////////////////////////////////////////////////////////
        console.log("Running key generation (used for source data)...");

        // Round 1 (party A)

        console.log("Round 1 (party A) started.");

        const kp1 = cc.KeyGen();

        // Generate evalmult key part for A
        const evalMultKey = cc.KeySwitchGen(kp1.secretKey, kp1.secretKey);

        // Generate evalsum key part for a
        cc.EvalSumKeyGen(kp1.secretKey);
        // note that the shared pointer construction is implicit in JS
        const evalSumKeys = cc.GetEvalSumKeyMap(kp1.secretKey.GetKeyTag());

        console.log("Round 1 of key generation completed");

        // Round 2 (party B)

        console.log("Round 2 (party B) started.");

        console.log("Joint public key for (s_a + s_b) is generated...");
        const kp2 = cc.MultipartyKeyGen(kp1.publicKey);

        const evalMultKey2 =
            cc.MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

        console.log(
            "Joint evaluation multiplication key for (s_a + s_b) is generated..."
        );
        const evalMultAB = cc.MultiAddEvalKeys(
            evalMultKey, evalMultKey2,
            kp2.publicKey.GetKeyTag());

        console.log(
            "Joint evaluation multiplication key for (s_a + s_b) is transformed..."
        );
        const evalMultBAB = cc.MultiMultEvalKey(
            evalMultAB, kp2.secretKey,
            kp2.publicKey.GetKeyTag());

        const evalSumKeysB = cc.MultiEvalSumKeyGen(
            kp2.secretKey, evalSumKeys,
            kp2.publicKey.GetKeyTag());

        console.log(
            "Joint evaluation summation key for (s_a + s_b) is generated..."
        );
        const evalSumKeysJoin = cc.MultiAddEvalSumKeys(
            evalSumKeys, evalSumKeysB,
            kp2.publicKey.GetKeyTag()
        );

        cc.InsertEvalSumKey(evalSumKeysJoin);

        console.log("Round 2 of key generation completed.");

        console.log("Round 3 (party A) started");

        console.log(
            "Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)..."
        );
        const evalMultAAB = cc.MultiMultEvalKey(
            evalMultAB, kp1.secretKey,
            kp2.publicKey.GetKeyTag());

        const evalMultFinal = cc.MultiAddEvalMultKeys(
            evalMultAAB, evalMultBAB,
            evalMultAB.GetKeyTag());

        cc.InsertEvalMultKey([evalMultFinal]);

        console.log("Round 3 of key generation completed");

        ////////////////////////////////////////////////////////////
        // Encode source data
        ////////////////////////////////////////////////////////////
        const vectorOfInts1 =
            new module.VectorDouble([1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0]);
        const vectorOfInts2 =
            new module.VectorDouble([1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]);
        const vectorOfInts3 =
            new module.VectorDouble([2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0]);

        ////////////////////////////////////////////////////////////
        // Encryption
        ////////////////////////////////////////////////////////////
        const plaintext1 = cc.MakeCKKSPackedPlaintext(vectorOfInts1);
        const plaintext2 = cc.MakeCKKSPackedPlaintext(vectorOfInts2);
        const plaintext3 = cc.MakeCKKSPackedPlaintext(vectorOfInts3);

        const ciphertext1 = cc.Encrypt(kp2.publicKey, plaintext1);
        const ciphertext2 = cc.Encrypt(kp2.publicKey, plaintext2);
        const ciphertext3 = cc.Encrypt(kp2.publicKey, plaintext3);

        ////////////////////////////////////////////////////////////
        // EvalAdd Operation on Re-Encrypted Data
        ////////////////////////////////////////////////////////////

        const ciphertextAdd12 = cc.EvalAddCipherCipher(ciphertext1, ciphertext2);
        const ciphertextAdd123 = cc.EvalAddCipherCipher(ciphertextAdd12, ciphertext3);

        const ciphertextMultTemp = cc.EvalMultCipherCipher(ciphertext1, ciphertext3);
        const ciphertextMult = cc.ModReduce(ciphertextMultTemp);
        const ciphertextEvalSum = cc.EvalSum(ciphertext3, batchSize);

        ////////////////////////////////////////////////////////////
        // Decryption after Accumulation Operation on Ecnrypted Data with Multiparty
        ////////////////////////////////////////////////////////////

        const cryptoParams = kp1.secretKey.GetCryptoParameters();
        const elementParams = cryptoParams.GetElementParams();

        // distributed decryption

        let ciphertextPartial1 =
            cc.MultipartyDecryptLead(kp1.secretKey, [ciphertextAdd123]);
        let ciphertextPartial2 =
            cc.MultipartyDecryptMain(kp2.secretKey, [ciphertextAdd123]);

        const plaintextMultipartyNew =
            cc.MultipartyDecryptFusion([
                ciphertextPartial1.get(0),
                ciphertextPartial2.get(0)
            ]);

        console.log("\n Original Plaintext: \n");
        console.log(plaintext1.toString());
        console.log(plaintext2.toString());
        console.log(plaintext3.toString());

        plaintextMultipartyNew.SetLength(plaintext1.GetLength());

        console.log("\n Resulting Fused Plaintext: \n");
        console.log(plaintextMultipartyNew.toString());

        ciphertextPartial1 =
            cc.MultipartyDecryptLead(kp1.secretKey, [ciphertextMult]);
        ciphertextPartial2 =
            cc.MultipartyDecryptMain(kp2.secretKey, [ciphertextMult]);

        const plaintextMultipartyMult =
            cc.MultipartyDecryptFusion([
                ciphertextPartial1.get(0),
                ciphertextPartial2.get(0)
            ]);

        plaintextMultipartyMult.SetLength(plaintext1.GetLength());

        console.log();
        console.log(
            " Resulting Fused Plaintext after Multiplication " +
            `of plaintexts 1 and 3: ${plaintextMultipartyMult}`
        );
        console.log();

        ciphertextPartial1 =
            cc.MultipartyDecryptLead(kp1.secretKey, [ciphertextEvalSum]);
        ciphertextPartial2 =
            cc.MultipartyDecryptMain(kp2.secretKey, [ciphertextEvalSum]);

        const plaintextMultipartyEvalSum =
            cc.MultipartyDecryptFusion([
                ciphertextPartial1.get(0),
                ciphertextPartial2.get(0)
            ]);

        plaintextMultipartyEvalSum.SetLength(plaintext1.GetLength());

        console.log("\n Fused result after the Summation of ciphertext 3: \n");
        console.log(plaintextMultipartyEvalSum.toString());

        return 0;
    } catch (exception) {
        console.error(module.getExceptionMessage(exception));
        return 1;
    }
}

main().then(exitCode => console.log(exitCode));
