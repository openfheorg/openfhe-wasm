// based on
// https://gitlab.com/palisade/palisade-development/-/blob/master/src/pke/examples/pre-buffer.cpp

const now = () => process.hrtime.bigint() / 1000000n

// generate a random integer since Math.random() in JS
// returns a value between 0 and 1
const INT_MAX = 2 << 32 - 1;
const rand = () => Math.floor(Math.random() * INT_MAX)

async function main() {

    const factory = require('../../../lib/openfhe_pke')
    const module = await factory()
    // Set the main parameters
    // all int types are number in typescript unless defined otherwise.
    const plaintextMod = 65537;
    const multDepth = 1;
    const scalingModSize = 60;
    let params = new module.CCParamsCryptoContextBFVRNS();
    params.SetPlaintextModulus(plaintextMod);
    console.log(`Plaintext Modulus was: ${params.GetPlaintextModulus()}`);

    params.SetMultiplicativeDepth(multDepth);
    params.SetScalingModSize(scalingModSize);
    console.log(`Mult Depth was: ${params.GetMultiplicativeDepth()}`);
    let cc = new module.GenCryptoContextBFV(params);

    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.PRE);
    cc.Enable(module.PKESchemeFeature.KEYSWITCH);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);

    let bla = cc.GetCryptoParameters();
    let blabla = bla.GetPlaintextModulus();
    console.log(`p = ${cc.GetCryptoParameters().GetPlaintextModulus()}`)
    console.log("n = " +
        cc
            .GetCryptoParameters()
            .GetElementParams()
            .GetCyclotomicOrder() / 2);

    console.log("log2 q = " +
        Math.log2(cc
            .GetCryptoParameters().GetElementParams().GetModulus()
            .ConvertToDouble()));

    console.log(`r = ${cc.GetCryptoParameters().GetDigitSize()}`)

    const ringsize = cc.GetRingDimension();
    console.log(`Alice can encrypt ${ringsize * 2} bytes of data`)

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////
    console.log("\nRunning Alice key generation (used for source data)...")

    let t = now();
    const keyPair1 = cc.KeyGen();
    console.log(`Key generation time: \t${now() - t} ms`)

    if (!keyPair1.good()) {
        console.log("Alice Key generation failed!");
        return 1;
    }

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    const nshort = ringsize;
    const vShortsJs = [];
    for (let i = 0; i < nshort; i++) vShortsJs.push(rand() % 65536);
    const vShorts = module.MakeVectorInt64Clipped(vShortsJs);

    const pt = cc.MakePackedPlaintext(vShorts, 1, 0);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    t = now();
    const ct1 = cc.Encrypt(keyPair1.publicKey, pt);
    console.log(`Encryption time: \t${now() - t} ms`);

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    t = now();
    const ptDec1 = cc.Decrypt(keyPair1.secretKey, ct1);
    console.log(`Decryption time: \t${now() - t} ms`);

    ptDec1.SetLength(pt.GetLength());

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    console.log("Bob Running key generation ...")

    t = now();
    const keyPair2 = cc.KeyGen();
    console.log(`Key generation time: \t${now() - t} ms`)

    if (!keyPair2.good()) {
        console.log("Bob Key generation failed!");
        return 1;
    }

    ////////////////////////////////////////////////////////////
    // Perform the proxy re-encryption key generation operation.
    // This generates the keys which are used to perform the key switching.
    ////////////////////////////////////////////////////////////

    console.log("\nGenerating proxy re-encryption key...");

    t = now();
    const reencryptionKey12 = cc.ReKeyGenPrivPub(
        keyPair1.secretKey,
        keyPair2.publicKey);

    console.log(`Key generation time: \t${now() - t} ms`)

    ////////////////////////////////////////////////////////////
    // Re-Encryption
    ////////////////////////////////////////////////////////////

    t = now();
    const ct2 = cc.ReEncrypt(reencryptionKey12, ct1);
    console.log(`Re-Encryption time: \t${now() - t} ms`)

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    t = now();
    const ptDec2 = cc.Decrypt(keyPair2.secretKey, ct2);
    console.log(`Decryption time: \t${now() - t} ms`)

    ptDec2.SetLength(pt.GetLength());

    const unpacked0 = pt.GetPackedValue();
    const unpacked1 = ptDec1.GetPackedValue();
    const unpacked2 = ptDec2.GetPackedValue();
    let good = true;

    // note that PALISADE assumes that plaintext is in the range of -p/2..p/2
    // to recover 0...q simply add q if the unpacked value is negative
    for (let i = 0; i < pt.GetLength(); i++) {
        if (unpacked1[i] < 0) unpacked1[i] += plaintextModulus;
        if (unpacked2[i] < 0) unpacked2[i] += plaintextModulus;
    }

    // compare all the results for correctness
    for (let i = 0; i < pt.GetLength(); i++) {
        if ((unpacked0[i] != unpacked1[i] || unpacked0[i] != unpacked2[i])) {
            console.log(`${i}, ${unpacked0[i]}, ${unpacked1[i]}, ${unpacked2[i]}`)
            good = false;
        }
    }

    if (good) console.log("PRE passes");
    else console.log("PRE fails");

    console.log("Execution Completed.")

    return good ? 0 : 1;
}

main().then(exitCode => console.log(exitCode));
