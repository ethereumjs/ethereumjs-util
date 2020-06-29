const BN = require('bn.js')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const getRandomBytes = require('crypto').randomBytes

const getPrivateKeys = function (count) {
  const privateKeys = []
  for (let i = 0; i < count; i++) {
    privateKeys.push(getRandomBytes(32))
  }

  return privateKeys
}

const getPrivateKey = function () {
  return getRandomBytes(32)
}

const getTweak = function () {
  return getRandomBytes(32)
}

const getMessage = function () {
  return getRandomBytes(32)
}

function getSignature (message, privateKey) {
  return sign(message, privateKey).signatureLowS
}

const getPublicKey = function (privateKey) {
  const publicKey = ec.keyFromPrivate(privateKey).getPublic()
  return {
    compressed: Buffer.from(publicKey.encode(null, true)),
    uncompressed: Buffer.from(publicKey.encode(null, false))
  }
}

const sign = function (message, privateKey) {
  const ecSig = ec.sign(message, privateKey, {canonical: false})

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

  sign: sign
}
