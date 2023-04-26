import factory from '../lib/openfhe_pke.js'
export function copyVecToJs(vec) {
    return new Array(vec.size()).fill(0).map((_, idx) => vec.get(idx));
}

export async function setupParamsBGV(params){

    const module = await factory();
    const plaintextMod = 65537;
    const multDepth = 2;
    const sDev = 3.2
    params.SetPlaintextModulus(plaintextMod);
    params.SetMultiplicativeDepth(multDepth);
    params.SetStandardDeviation(sDev);
    params.SetSecurityLevel(module.SecurityLevel.HEStd_128_classic);
    params.SetSecretKeyDist(module.SecretKeyDist.UNIFORM_TERNARY);
    params.SetKeySwitchTechnique(module.KeySwitchTechnique.HYBRID);
    return params;
}


export async function setupCCBGV(cc) {

    const module = await factory();
    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.PRE);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);

    let kp = cc.KeyGen();
    cc.EvalMultKeyGen(kp.secretKey);
    cc.EvalAtIndexKeyGen(kp.secretKey, [1, 2, -1, -2]);
    return [cc, kp];
}

export async function setupBGVFull(){

    const module = await factory();
    const plaintextMod = 65537;
    const multDepth = 2;
    const sDev = 3.2

    let params = await new module.CCParamsCryptoContextBGVRNS();
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
    return [cc, kp];
}