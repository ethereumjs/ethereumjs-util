import * as secp256k1 from 'ethereum-cryptography/secp256k1'
const wrapper = require('./lib/secp256k1')
const der = require('./lib/der')

export interface SignOptions {
  data?: Buffer
  noncefn?: (
    message: Uint8Array,
    privateKey: Uint8Array,
    algo: Uint8Array | null,
    data: Uint8Array | null,
    attempt: number,
  ) => Uint8Array
}

export const privateKeyVerify = function(privateKey: Buffer): boolean {
  return secp256k1.privateKeyVerify(Uint8Array.from(privateKey))
}

export const privateKeyExport = function(privateKey: Buffer, compressed?: boolean): Buffer {
  if (privateKey.length !== 32) {
    throw new RangeError('private key length is invalid')
  }

  const publicKey = wrapper.privateKeyExport(privateKey, compressed)

  return der.privateKeyExport(privateKey, publicKey, compressed)
}

export const privateKeyImport = function(privateKey: Buffer): Buffer {
  privateKey = der.privateKeyImport(privateKey)
  if (privateKey !== null && privateKey.length === 32 && privateKeyVerify(privateKey)) {
    return privateKey
  }

  throw new Error("couldn't import from DER format")
}

export const privateKeyNegate = function(privateKey: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyNegate(Uint8Array.from(privateKey)))
}

export const privateKeyModInverse = function(privateKey: Buffer): Buffer {
  if (privateKey.length !== 32) {
    throw new Error('private key length is invalid')
  }

  return Buffer.from(wrapper.privateKeyModInverse(Uint8Array.from(privateKey)))
}

export const privateKeyTweakAdd = function(privateKey: Buffer, tweak: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyTweakAdd(Uint8Array.from(privateKey), tweak))
}

export const privateKeyTweakMul = function(privateKey: Buffer, tweak: Buffer): Buffer {
  return Buffer.from(
    secp256k1.privateKeyTweakMul(Uint8Array.from(privateKey), Uint8Array.from(tweak)),
  )
}

export const publicKeyCreate = function(privateKey: Buffer, compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.publicKeyCreate(Uint8Array.from(privateKey), compressed))
}

export const publicKeyConvert = function(publicKey: Buffer, compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.publicKeyConvert(Uint8Array.from(publicKey), compressed))
}

export const publicKeyVerify = function(publicKey: Buffer): boolean {
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    return false
  }

  return secp256k1.publicKeyVerify(Uint8Array.from(publicKey))
}

export const publicKeyTweakAdd = function(
  publicKey: Buffer,
  tweak: Buffer,
  compressed?: boolean,
): Buffer {
  return Buffer.from(
    secp256k1.publicKeyTweakAdd(Uint8Array.from(publicKey), Uint8Array.from(tweak), compressed),
  )
}

export const publicKeyTweakMul = function(
  publicKey: Buffer,
  tweak: Buffer,
  compressed?: boolean,
): Buffer {
  return Buffer.from(
    secp256k1.publicKeyTweakMul(Uint8Array.from(publicKey), Uint8Array.from(tweak), compressed),
  )
}

export const publicKeyCombine = function(publicKeys: Buffer[], compressed?: boolean): Buffer {
  const keys: Uint8Array[] = []
  publicKeys.forEach((publicKey: Buffer) => {
    keys.push(Uint8Array.from(publicKey))
  })

  return Buffer.from(secp256k1.publicKeyCombine(keys, compressed))
}

export const signatureNormalize = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureNormalize(Uint8Array.from(signature)))
}

export const signatureExport = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureExport(Uint8Array.from(signature)))
}

export const signatureImport = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureImport(Uint8Array.from(signature)))
}

export const signatureImportLax = function(signature: Buffer): Buffer {
  if (signature.length === 0) {
    throw new RangeError('signature length is invalid')
  }

  const sigObj = der.signatureImportLax(signature)
  if (sigObj === null) {
    throw new Error("couldn't parse DER signature")
  }

  return wrapper.signatureImport(sigObj)
}

export const sign = function(
  message: Buffer,
  privateKey: Buffer,
  options?: SignOptions,
): { signature: Buffer; recovery: number } {
  if (options != null) {
    if (options.data != null && options.data.length != 32) {
      throw new RangeError('options.data length is invalid')
    }
  }

  const sig = secp256k1.ecdsaSign(Uint8Array.from(message), Uint8Array.from(privateKey), options)

  return {
    signature: Buffer.from(sig.signature),
    recovery: sig.recid,
  }
}

export const verify = function(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  return secp256k1.ecdsaVerify(Uint8Array.from(signature), Uint8Array.from(message), publicKey)
}

export const recover = function(
  message: Buffer,
  signature: Buffer,
  recid: number,
  compressed?: boolean,
): Buffer {
  return Buffer.from(
    secp256k1.ecdsaRecover(Uint8Array.from(signature), recid, Uint8Array.from(message), compressed),
  )
}

export const ecdh = function(publicKey: Buffer, privateKey: Buffer): Buffer {
  return Buffer.from(secp256k1.ecdh(Uint8Array.from(publicKey), Uint8Array.from(privateKey), {}))
}

export const ecdhUnsafe = function(
  publicKey: Buffer,
  privateKey: Buffer,
  compressed?: boolean,
): Buffer {
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new RangeError('public key length is invalid')
  }

  if (privateKey.length !== 32) {
    throw new RangeError('private key length is invalid')
  }

  return Buffer.from(
    wrapper.ecdhUnsafe(Uint8Array.from(publicKey), Uint8Array.from(privateKey), compressed),
  )
}
