async function main() {
    const factory = require('../../../lib/openfhe_pke')
    const module = await factory()
    // Set the main parameters
    // all int types are number in typescript unless defined otherwise.
    let params = new module.CCParamsCryptoContextBFVRNS();
    params.SetPlaintextModulus(65537);
    params.SetMultiplicativeDepth(2);
    let cc = new module.GenCryptoContextBFV(params);

    if (module.PrecomputeCRTTablesAfterDeserializaton()){
        console.log("PrecomputeCRTTablesAfterDeserializaton originally true");
        module.DisablePrecomputeCRTTablesAfterDeserializaton();
        console.log(`PrecomputeCRTTablesAfterDeserializaton after disabling: ${
            module.PrecomputeCRTTablesAfterDeserializaton()
        }`);
        module.EnablePrecomputeCRTTablesAfterDeserializaton();
        console.log(`PrecomputeCRTTablesAfterDeserializaton after enabling: ${
            module.PrecomputeCRTTablesAfterDeserializaton()
        }`);
    } else {
        console.log("PrecomputeCRTTablesAfterDeserializaton originally false");
        module.EnablePrecomputeCRTTablesAfterDeserializaton();
        console.log(`PrecomputeCRTTablesAfterDeserializaton after enabling: ${
            module.PrecomputeCRTTablesAfterDeserializaton()
        }`);
        module.DisablePrecomputeCRTTablesAfterDeserializaton();
        console.log(`PrecomputeCRTTablesAfterDeserializaton after disabling: ${
            module.PrecomputeCRTTablesAfterDeserializaton()
        }`);
    }

    module.EnablePrecomputeCRTTablesAfterDeserializaton();
    console.log()

    return 0;
}

main().then(exitCode => console.log(exitCode));
