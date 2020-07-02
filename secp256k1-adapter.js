import * as secp256k1 from 'ethereum-cryptography/secp256k1'

const secp256k1v3 = require('./secp256k1-lib/index')
const der = require('./secp256k1-lib/der')

const privateKeyVerify = function (privateKey) {
  if (privateKey.length !== 32) {
    return false
  }

  return secp256k1.privateKeyVerify(Uint8Array.from(privateKey))
}

const privateKeyExport = function (privateKey, compressed) {
  if (privateKey.length !== 32) {
    throw new RangeError('private key length is invalid')
  }

  const publicKey = secp256k1v3.privateKeyExport(privateKey, compressed)

  return der.privateKeyExport(privateKey, publicKey, compressed)
}

const privateKeyImport = function (privateKey) {
  privateKey = der.privateKeyImport(privateKey)
  if (privateKey !== null && privateKey.length === 32 && privateKeyVerify(privateKey)) {
    return privateKey
  }

  throw new Error("couldn't import from DER format")
}

const privateKeyNegate = function (privateKey) {
  return Buffer.from(secp256k1.privateKeyNegate(Uint8Array.from(privateKey)))
}

const privateKeyModInverse = function (privateKey) {
  if (privateKey.length !== 32) {
    throw new Error('private key length is invalid')
  }

  return Buffer.from(secp256k1v3.privateKeyModInverse(Uint8Array.from(privateKey)))
}

const privateKeyTweakAdd = function (privateKey, tweak) {
  return Buffer.from(secp256k1.privateKeyTweakAdd(Uint8Array.from(privateKey), tweak))
}

const privateKeyTweakMul = function (privateKey, tweak) {
  return Buffer.from(
    secp256k1.privateKeyTweakMul(Uint8Array.from(privateKey), Uint8Array.from(tweak))
  )
}

const publicKeyCreate = function (privateKey, compressed) {
  return Buffer.from(secp256k1.publicKeyCreate(Uint8Array.from(privateKey), compressed))
}

const publicKeyConvert = function (publicKey, compressed) {
  return Buffer.from(secp256k1.publicKeyConvert(Uint8Array.from(publicKey), compressed))
}

const publicKeyVerify = function (publicKey) {
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    return false
  }

  return secp256k1.publicKeyVerify(Uint8Array.from(publicKey))
}

const publicKeyTweakAdd = function (publicKey, tweak, compressed) {
  return Buffer.from(
    secp256k1.publicKeyTweakAdd(Uint8Array.from(publicKey), Uint8Array.from(tweak), compressed)
  )
}

const publicKeyTweakMul = function (publicKey, tweak, compressed) {
  return Buffer.from(
    secp256k1.publicKeyTweakMul(Uint8Array.from(publicKey), Uint8Array.from(tweak), compressed)
  )
}

const publicKeyCombine = function (publicKeys, compressed) {
  const keys = []
  publicKeys.forEach((publicKey) => {
    keys.push(Uint8Array.from(publicKey))
  })

  return Buffer.from(secp256k1.publicKeyCombine(keys, compressed))
}

const signatureNormalize = function (signature) {
  return Buffer.from(secp256k1.signatureNormalize(Uint8Array.from(signature)))
}

const signatureExport = function (signature) {
  return Buffer.from(secp256k1.signatureExport(Uint8Array.from(signature)))
}

const signatureImport = function (signature) {
  return Buffer.from(secp256k1.signatureImport(Uint8Array.from(signature)))
}

const signatureImportLax = function (signature) {
  if (signature.length === 0) {
    throw new RangeError('signature length is invalid')
  }

  const sigObj = der.signatureImportLax(signature)
  if (sigObj === null) {
    throw new Error("couldn't parse DER signature")
  }

  return secp256k1v3.signatureImport(sigObj)
}

const sign = function (message, privateKey, options) {
  if (options === null) {
    throw new TypeError('options should be an Object')
  }

  let signOptions

  if (options) {
    signOptions = {}

    if (options.data === null) {
      throw new TypeError('options.data should be a Buffer')
    }

    if (options.data) {
      if (options.data.length !== 32) {
        throw new RangeError('options.data length is invalid')
      }

      signOptions.data = new Uint8Array(options.data)
    }

    if (options.noncefn === null) {
      throw new TypeError('options.noncefn should be a Function')
    }

    if (options.noncefn) {
      signOptions.noncefn = (message, privateKey, algo, data, attempt) => {
        const bufferAlgo = algo != null ? Buffer.from(algo) : null
        const bufferData = data != null ? Buffer.from(data) : null

        let buffer = Buffer.from('')

        if (options.noncefn) {
          buffer = options.noncefn(Buffer.from(message),
            Buffer.from(privateKey),
            bufferAlgo,
            bufferData,
            attempt
          )
        }

        return new Uint8Array(buffer)
      }
    }
  }

  const sig = secp256k1.ecdsaSign(
    Uint8Array.from(message),
    Uint8Array.from(privateKey),
    signOptions
  )

  return {
    signature: Buffer.from(sig.signature),
    recovery: sig.recid
  }
}

const verify = function (message, signature, publicKey) {
  return secp256k1.ecdsaVerify(Uint8Array.from(signature), Uint8Array.from(message), publicKey)
}

const recover = function (message, signature, recid, compressed) {
  return Buffer.from(
    secp256k1.ecdsaRecover(Uint8Array.from(signature), recid, Uint8Array.from(message), compressed)
  )
}

const ecdh = function (publicKey, privateKey) {
  return Buffer.from(secp256k1.ecdh(Uint8Array.from(publicKey), Uint8Array.from(privateKey), {}))
}

const ecdhUnsafe = function (publicKey, privateKey, compressed) {
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new RangeError('public key length is invalid')
  }

  if (privateKey.length !== 32) {
    throw new RangeError('private key length is invalid')
  }

  return Buffer.from(
    secp256k1v3.ecdhUnsafe(Uint8Array.from(publicKey), Uint8Array.from(privateKey), compressed)
  )
}

module.exports = {
  privateKeyVerify: privateKeyVerify,
  privateKeyExport: privateKeyExport,
  privateKeyImport: privateKeyImport,
  privateKeyNegate: privateKeyNegate,
  privateKeyModInverse: privateKeyModInverse,
  privateKeyTweakAdd: privateKeyTweakAdd,
  privateKeyTweakMul: privateKeyTweakMul,

  publicKeyCreate: publicKeyCreate,
  publicKeyConvert: publicKeyConvert,
  publicKeyVerify: publicKeyVerify,
  publicKeyTweakAdd: publicKeyTweakAdd,
  publicKeyTweakMul: publicKeyTweakMul,
  publicKeyCombine: publicKeyCombine,

  signatureNormalize: signatureNormalize,
  signatureExport: signatureExport,
  signatureImport: signatureImport,
  signatureImportLax: signatureImportLax,

  sign: sign,
  verify: verify,
  recover: recover,

  ecdh: ecdh,
  ecdhUnsafe: ecdhUnsafe
}
