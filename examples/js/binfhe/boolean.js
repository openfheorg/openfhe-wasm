// follows boolean.cpp example
async function main() {
    const factory = require('../../../lib/openfhe_binfhe')
    const module = await factory()
    const cc = new module.BinFHEContext()
    cc.GenerateBinFHEContext(module.BINFHE_PARAMSET.STD128, module.BINFHE_METHOD.GINX);
    console.log('Starting to generate keys.')
    const sk = cc.KeyGen()
    console.log('SK Generated')
    cc.BTKeyGen(sk)
    console.log('Completed generating keys.')

    console.log('Encrypting...')
    const ct1 = cc.Encrypt(sk, 1)
    const ct2 = cc.Encrypt(sk, 2)

    console.log('Computing...')
    const ctAND1 = cc.EvalBinGate(module.BINGATE.AND, ct1, ct2)
    const ct2Not = cc.EvalNOT(ct2)
    const ctAND2 = cc.EvalBinGate(module.BINGATE.AND, ct2Not, ct1)
    const ctResult = cc.EvalBinGate(module.BINGATE.OR, ctAND1, ctAND2)

    console.log('Decrypting...')
    const result = cc.Decrypt(sk, ctResult)
    console.log(
        'Result of encrypted computation of ' +
        '(1 AND 1) OR (1 AND (NOT 1) = ' + result)

    // since javascript cannot detect variables going out of scope reliably,
    // we must delete the crypto context manually
    cc.delete();
    return 0
}

main().then(exitCode => console.log(exitCode))
