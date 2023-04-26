import factory from '../lib/openfhe_pke.js'
export function copyVecToJs(vec) {
    return new Array(vec.size()).fill(0).map((_, idx) => vec.get(idx));
}

//////////////////////////////////////////////
// BFV
//////////////////////////////////////////////

export async function setupParamsBFV(params) {

    const module = await factory();
    const plaintextMod = 65537;
    const multDepth = 2;
    const sDev = 3.2
    params.SetPlaintextModulus(plaintextMod);
    params.SetMultiplicativeDepth(multDepth);
    params.SetStandardDeviation(sDev);
    params.SetSecurityLevel(module.SecurityLevel.HEStd_128_classic);
    params.SetSecretKeyDist(module.SecretKeyDist.UNIFORM_TERNARY);
    return params;
}


export async function setupCCBFV(cc, indices=undefined) {
    const module = await factory();
    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.PRE);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);
    cc.Enable(module.PKESchemeFeature.ADVANCEDSHE);
    cc.Enable(module.PKESchemeFeature.FHE);
    //
    let kp = cc.KeyGen();
    // cc.EvalSumKeyGen(kp.secretKey);
    cc.EvalMultKeyGen(kp.secretKey);
    if (indices !== undefined) {
        cc.EvalAtIndexKeyGen(kp.secretKey, indices);
    }
    return [cc, kp];
}

//////////////////////////////////////////////
// BGV
//////////////////////////////////////////////

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


export async function setupCCBGV(cc, indices=undefined) {

    const module = await factory();
    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.PRE);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);
    cc.Enable(module.PKESchemeFeature.ADVANCEDSHE);
    cc.Enable(module.PKESchemeFeature.FHE);

    let kp = cc.KeyGen();
    cc.EvalSumKeyGen(kp.secretKey);
    cc.EvalMultKeyGen(kp.secretKey);

    if (indices !== undefined) {
        cc.EvalAtIndexKeyGen(kp.secretKey, indices);
    }
    return [cc, kp];
}

//////////////////////////////////////////////
// CKKS
//////////////////////////////////////////////


export async function setupParamsCKKS(params) {

    const module = await factory();
    const multDepth = 3;
    const batchSize = 8;
    const scalingModSize = 50;

    params.SetScalingModSize(scalingModSize);
    params.SetBatchSize(batchSize);
    params.SetMultiplicativeDepth(multDepth);
    params.SetSecurityLevel(module.SecurityLevel.HEStd_128_classic);
    return params;
}


export async function setupCCCKKS(cc, indices=undefined) {

    const module = await factory();
    cc.Enable(module.PKESchemeFeature.PKE);
    cc.Enable(module.PKESchemeFeature.PRE);
    cc.Enable(module.PKESchemeFeature.LEVELEDSHE);
    cc.Enable(module.PKESchemeFeature.ADVANCEDSHE);

    let kp = cc.KeyGen();
    cc.EvalSumKeyGen(kp.secretKey);
    cc.EvalMultKeyGen(kp.secretKey);
    if (indices !== undefined){
        cc.EvalAtIndexKeyGen(kp.secretKey, indices);
    }
    return [cc, kp];
}
