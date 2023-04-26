import factory from '../lib/openfhe_pke.js'
export function copyVecToJs(vec) {
    return new Array(vec.size()).fill(0).map((_, idx) => vec.get(idx));
}

export async function setupParams(params){

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