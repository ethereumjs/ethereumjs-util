// This file is imported from secp256k1 v3
// https://github.com/cryptocoinjs/secp256k1-node/blob/master/LICENSE

const BN = require('bn.js')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const getRandomBytes = require('crypto').randomBytes

function getPrivateKeys(count) {
    const privateKeys = []
    for (let i = 0; i < count; i++) {
        privateKeys.push(getRandomBytes(32))
    }

    return privateKeys
}

function getPrivateKey() {
    return getRandomBytes(32)
}

function getTweak() {
    return getRandomBytes(32)
}

function getMessage () {
    return getRandomBytes(32)
}

function getSignature (message, privateKey) {
    return sign(message, privateKey).signatureLowS
}

function getPublicKeys(privateKeys) {
    const publicKeys = []
    privateKeys.forEach((privateKey) => {
        const publicKey = ec.keyFromPrivate(privateKey).getPublic()
        publicKeys.push({
            compressed: Buffer.from(publicKey.encode(null, true)),
            uncompressed: Buffer.from(publicKey.encode(null, false))
        })
    })

    return publicKeys
}

function getPublicKey(privateKey) {
    const publicKey = ec.keyFromPrivate(privateKey).getPublic()
    return {
        compressed: Buffer.from(publicKey.encode(null, true)),
        uncompressed: Buffer.from(publicKey.encode(null, false))
    }
}

function sign (message, privateKey) {
    const ecSig = ec.sign(message, privateKey, { canonical: false })

    const signature = Buffer.concat([
        ecSig.r.toArrayLike(Buffer, 'be', 32),
        ecSig.s.toArrayLike(Buffer, 'be', 32)
    ])
    let recovery = ecSig.recoveryParam
    if (ecSig.s.cmp(ec.nh) === 1) {
        ecSig.s = ec.n.sub(ecSig.s)
        recovery ^= 1
    }
    const signatureLowS = Buffer.concat([
        ecSig.r.toArrayLike(Buffer, 'be', 32),
        ecSig.s.toArrayLike(Buffer, 'be', 32)
    ])

    return {
        signature: signature,
        signatureLowS: signatureLowS,
        recovery: recovery
    }
}

module.exports = {
    ec: ec,
    BN_ZERO: new BN(0),
    BN_ONE: new BN(1),

    getPrivateKeys: getPrivateKeys,
    getPrivateKey: getPrivateKey,
    getPublicKey: getPublicKey,
    getTweak: getTweak,
    getMessage: getMessage,
    getSignature: getSignature,

    sign: sign,
}
