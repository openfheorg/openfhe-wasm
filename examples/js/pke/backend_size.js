async function main() {
    const factory = require('../../../lib/openfhe_pke')
    const module = await factory()

    console.log(module.GetBackendSize());
    return 0;
}

main().then(exitCode => console.log(exitCode));
