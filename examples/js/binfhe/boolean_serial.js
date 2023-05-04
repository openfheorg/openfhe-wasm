// follows boolean-serial-binary.cpp example
async function main() {
    const factory = require('../../../lib/openfhe_binfhe')
    const module = await factory()
    try {

        // Generating the crypto context
        const cc1 = new module.BinFHEContext()
        cc1.GenerateBinFHEContext(
            module.BINFHE_PARAMSET.TOY,
            module.BINFHE_METHOD.GINX
        )
        console.log("Generating keys.")

        // Generating the secret key
        const sk1 = cc1.KeyGen();

        // Generating the bootstrapping keys
        cc1.BTKeyGen(sk1)

        console.log("Done generating all keys.")

        // Encryption for a ciphertext that will be serialized
        const ct1 = cc1.Encrypt(sk1, 1);

        // CODE FOR SERIALIZATION

        // Serializing key-independent crypto context

        const cryptoContextBuffer =
            module.SerializeCryptoContextToBuffer(cc1, module.SerType.BINARY);
        console.log("The cryptocontext has been serialized.");

        // Serializing refreshing and key switching keys (needed for bootstrapping)
        //
        const _refreshKey = cc1.GetRefreshKey();
        const refreshKeyBuffer =
            module.SerializeRefreshKeyToBuffer(_refreshKey, module.SerType.BINARY);
        console.log("The refreshing key has been serialized.")

        const _switchKey = cc1.GetSwitchKey();
        const ksKeyBuffer =
            module.SerializeSwitchingKeyToBuffer(_switchKey, module.SerType.BINARY);
        console.log("The key switching key has been serialized.")

        // Serializing private keys

        const sk1Buffer =
            module.SerializePrivateKeyToBuffer(sk1, module.SerType.BINARY);
        console.log("The secret key sk1 key has been serialized")

        // Serializing a ciphertext

        const ct1Buffer =
            module.SerializeCiphertextToBuffer(ct1, module.SerType.BINARY);

        // CODE FOR DESERIALIZATION

        // Deserializing the cryptocontext

        const cc =
            module.DeserializeCryptoContextFromBuffer(cryptoContextBuffer, module.SerType.BINARY);
        console.log("The cryptocontext has been deserialized");

        // deserializing the refreshing and switching keys (for bootstrapping)

        const refreshKey =
            module.DeserializeRefreshKeyFromBuffer(refreshKeyBuffer, module.SerType.BINARY);
        console.log("The refresh key has been deserialized");

        const ksKey =
            module.DeserializeSwitchingKeyFromBuffer(ksKeyBuffer, module.SerType.BINARY);
        console.log("The key switching key has been deserialized");

        // Loading the keys in the cryptocontext
        cc.BTKeyLoad(refreshKey, ksKey);

        // Deserializing the secret key

        const sk =
            module.DeserializePrivateKeyFromBuffer(sk1Buffer, module.SerType.BINARY);
        console.log("The secret key has been deserialized");

        // Deserializing a previously serialized ciphertext

        const ct =
            module.DeserializeCiphertextFromBuffer(ct1Buffer, module.SerType.BINARY);
        console.log("The ciphertext has been deserialized");

        // OPERATIONS WITH DESERIALIZED KEYS AND CIPHERTEXTS

        const ct2 = cc.Encrypt(sk, 1);

        console.log("Running the computation");

        const ctResult = cc.EvalBinGate(module.BINGATE.AND, ct, ct2);

        console.log("The computation has been completed");

        const result = cc.Decrypt(sk, ctResult);

        console.log(`result of 1 AND 1 = ${result}`)

        return 0
    } catch (err) {
        if (typeof err === 'number')
            console.log(module.getExceptionMessage(err))
        else
            console.log(err)
        return 1;
    }
}

main().then(exitCode => console.log(exitCode))

