// based on
// https://gitlab.com/palisade/palisade-development/-/blob/master/src/pke/examples/pre-buffer.cpp

const now = () => process.hrtime.bigint() / 1000000n

// generate a random integer since Math.random() in JS
// returns a value between 0 and 1
const INT_MAX = 2 << 32 - 1;
const rand = () => Math.floor(Math.random() * INT_MAX)

async function main() {
    const module = await require('../../../lib/openfhe_pke')()

    console.log("setting up BFV RNS crypto system")
    const plaintextModulus = 65537;

    const multDepth = 1;

    const sigma = 3.2;
    const securityLevel = module.SecurityLevel.HEStd_128_classic;

    const cc = module.GenCryptoContextBFVrns(
        plaintextModulus, securityLevel, sigma, 0, multDepth, 0,
        module.MODE.OPTIMIZED);

    cc.Enable(module.PKESchemeFeature.ENCRYPTION);
    cc.Enable(module.PKESchemeFeature.SHE);
    cc.Enable(module.PKESchemeFeature.PRE);

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

    console.log(`r = ${cc.GetCryptoParameters().GetRelinWindow()}`)

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

    const pt = cc.MakePackedPlaintext(vShorts);

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
    const reencryptionKey12 = cc.ReKeyGen(
        keyPair2.publicKey, keyPair1.secretKey);

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
