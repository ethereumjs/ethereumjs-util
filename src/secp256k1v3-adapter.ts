const secp256k1 = require('ethereum-cryptography/secp256k1')
const secp256k1v3 = require('./secp256k1v3-lib/index')
const der = require('./secp256k1v3-lib/der')

export interface SignOptions {
  data?: Buffer
  noncefn?: (
    message: Buffer,
    privateKey: Buffer,
    algo: Buffer | null,
    data: Buffer | null,
    attempt: number,
  ) => Buffer
}

export interface SignOptionsV4 {
  data?: Uint8Array
  noncefn?: (
    message: Uint8Array,
    privateKey: Uint8Array,
    algo: Uint8Array | null,
    data: Uint8Array | null,
    attempt: number,
  ) => Uint8Array
}

/**
 * Verify an ECDSA privateKey
 * @method privateKeyVerify
 * @param {Buffer} privateKey
 * @return {boolean}
 */
export const privateKeyVerify = function(privateKey: Buffer): boolean {
  // secp256k1 v4 version throws when privateKey length is not 32
  if (privateKey.length !== 32) {
    return false
  }

  return secp256k1.privateKeyVerify(Uint8Array.from(privateKey))
}

/**
 * Export a privateKey in DER format
 * @method privateKeyExport
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {boolean}
 */
export const privateKeyExport = function(privateKey: Buffer, compressed?: boolean): Buffer {
  // secp256k1 v4 version throws when privateKey length is not 32
  if (privateKey.length !== 32) {
    throw new RangeError('private key length is invalid')
  }

  const publicKey = secp256k1v3.privateKeyExport(privateKey, compressed)

  return der.privateKeyExport(privateKey, publicKey, compressed)
}

/**
 * Import a privateKey in DER format
 * @method privateKeyImport
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
export const privateKeyImport = function(privateKey: Buffer): Buffer {
  // privateKeyImport method is not part of secp256k1 v4 package
  // this implementation is based on v3
  privateKey = der.privateKeyImport(privateKey)
  if (privateKey !== null && privateKey.length === 32 && privateKeyVerify(privateKey)) {
    return privateKey
  }

  throw new Error("couldn't import from DER format")
}

/**
 * Negate a privateKey by subtracting it from the order of the curve's base point
 * @method privateKeyNegate
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
export const privateKeyNegate = function(privateKey: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyNegate(Uint8Array.from(privateKey)))
}

/**
 * Compute the inverse of a privateKey (modulo the order of the curve's base point).
 * @method privateKeyModInverse
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
export const privateKeyModInverse = function(privateKey: Buffer): Buffer {
  if (privateKey.length !== 32) {
    throw new Error('private key length is invalid')
  }

  return Buffer.from(secp256k1v3.privateKeyModInverse(Uint8Array.from(privateKey)))
}

/**
 * Tweak a privateKey by adding tweak to it.
 * @method privateKeyTweakAdd
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
export const privateKeyTweakAdd = function(privateKey: Buffer, tweak: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyTweakAdd(Uint8Array.from(privateKey), tweak))
}

/**
 * Tweak a privateKey by multiplying it by a tweak.
 * @method privateKeyTweakMul
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
export const privateKeyTweakMul = function(privateKey: Buffer, tweak: Buffer): Buffer {
  return Buffer.from(
    secp256k1.privateKeyTweakMul(Uint8Array.from(privateKey), Uint8Array.from(tweak)),
  )
}

/**
 * Compute the public key for a privateKey.
 * @method publicKeyCreate
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
export const publicKeyCreate = function(privateKey: Buffer, compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.publicKeyCreate(Uint8Array.from(privateKey), compressed))
}

/**
 * Convert a publicKey to compressed or uncompressed form.
 * @method publicKeyConvert
 * @param {Buffer} publicKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
export const publicKeyConvert = function(publicKey: Buffer, compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.publicKeyConvert(Uint8Array.from(publicKey), compressed))
}

/**
 * Verify an ECDSA publicKey.
 * @method publicKeyVerify
 * @param {Buffer} publicKey
 * @return {boolean}
 */
export const publicKeyVerify = function(publicKey: Buffer): boolean {
  // secp256k1 v4 version throws when publicKey length is not 33 or 65
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    return false
  }

  return secp256k1.publicKeyVerify(Uint8Array.from(publicKey))
}

/**
 * Tweak a publicKey by adding tweak times the generator to it.
 * @method publicKeyTweakAdd
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} compressed
 * @return {Buffer}
 */
export const publicKeyTweakAdd = function(
  publicKey: Buffer,
  tweak: Buffer,
  compressed?: boolean,
): Buffer {
  return Buffer.from(
    secp256k1.publicKeyTweakAdd(Uint8Array.from(publicKey), Uint8Array.from(tweak), compressed),
  )
}

/**
 * Tweak a publicKey by multiplying it by a tweak value
 * @method publicKeyTweakMul
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} compressed
 * @return {Buffer}
 */
export const publicKeyTweakMul = function(
  publicKey: Buffer,
  tweak: Buffer,
  compressed?: boolean,
): Buffer {
  return Buffer.from(
    secp256k1.publicKeyTweakMul(Uint8Array.from(publicKey), Uint8Array.from(tweak), compressed),
  )
}

/**
 * Add a given publicKeys together.
 * @method publicKeyCombine
 * @param {Array<Buffer>} publicKeys
 * @param {boolean} compressed
 * @return {Buffer}
 */
export const publicKeyCombine = function(publicKeys: Buffer[], compressed?: boolean): Buffer {
  const keys: Uint8Array[] = []
  publicKeys.forEach((publicKey: Buffer) => {
    keys.push(Uint8Array.from(publicKey))
  })

  return Buffer.from(secp256k1.publicKeyCombine(keys, compressed))
}

/**
 * Convert a signature to a normalized lower-S form.
 * @method signatureNormalize
 * @param {Buffer} signature
 * @return {Buffer}
 */
export const signatureNormalize = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureNormalize(Uint8Array.from(signature)))
}

/**
 * Serialize an ECDSA signature in DER format.
 * @method signatureExport
 * @param {Buffer} signature
 * @return {Buffer}
 */
export const signatureExport = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureExport(Uint8Array.from(signature)))
}

/**
 * Parse a DER ECDSA signature (follow by [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)).
 * @method signatureImport
 * @param {Buffer} signature
 * @return {Buffer}
 */
export const signatureImport = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureImport(Uint8Array.from(signature)))
}

/**
 * Parse a DER ECDSA signature (not follow by [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)).
 * @method signatureImportLax
 * @param {Buffer} signature
 * @return {Buffer}
 */
export const signatureImportLax = function(signature: Buffer): Buffer {
  // signatureImportLax method is not part of secp256k1 v4 package
  // this implementation is based on v3
  // ensure that signature is greater than 0
  if (signature.length === 0) {
    throw new RangeError('signature length is invalid')
  }

  const sigObj = der.signatureImportLax(signature)
  if (sigObj === null) {
    throw new Error("couldn't parse DER signature")
  }

  return secp256k1v3.signatureImport(sigObj)
}

/**
 * Create an ECDSA signature. Always return low-S signature.
 * @method sign
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {Object} options
 * @return {Buffer}
 */
export const sign = function(
  message: Buffer,
  privateKey: Buffer,
  options?: SignOptions,
): { signature: Buffer; recovery: number } {
  if (options === null) {
    throw new TypeError('options should be an Object')
  }

  let signOptions: SignOptionsV4 | undefined = undefined

  if (options) {
    signOptions = {}

    if (options.data === null) {
      // validate option.data length
      throw new TypeError('options.data should be a Buffer')
    }

    if (options.data) {
      if (options.data.length != 32) {
        throw new RangeError('options.data length is invalid')
      }

      signOptions.data = new Uint8Array(options.data)
    }

    if (options.noncefn === null) {
      throw new TypeError('options.noncefn should be a Function')
    }

    if (options.noncefn) {
      // convert option.noncefn function signature
      signOptions.noncefn = (
        message: Uint8Array,
        privateKey: Uint8Array,
        algo: Uint8Array | null,
        data: Uint8Array | null,
        attempt: number,
      ) => {
        const bufferAlgo: Buffer | null = algo != null ? Buffer.from(algo) : null
        const bufferData: Buffer | null = data != null ? Buffer.from(data) : null

        let buffer: Buffer = Buffer.from('')

        if (options.noncefn) {
          buffer = options.noncefn(
            Buffer.from(message),
            Buffer.from(privateKey),
            bufferAlgo,
            bufferData,
            attempt,
          )
        }

        return new Uint8Array(buffer)
      }
    }
  }

  const sig = secp256k1.ecdsaSign(
    Uint8Array.from(message),
    Uint8Array.from(privateKey),
    signOptions,
  )

  return {
    signature: Buffer.from(sig.signature),
    recovery: sig.recid,
  }
}

/**
 * Verify an ECDSA signature.
 * @method verify
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @return {boolean}
 */
export const verify = function(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  return secp256k1.ecdsaVerify(Uint8Array.from(signature), Uint8Array.from(message), publicKey)
}

/**
 * Recover an ECDSA public key from a signature.
 * @method recover
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Number} recid
 * @param {boolean} compressed
 * @return {Buffer}
 */
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

/**
 * Compute an EC Diffie-Hellman secret and applied sha256 to compressed public key.
 * @method ecdh
 * @param {Buffer} publicKey
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
export const ecdh = function(publicKey: Buffer, privateKey: Buffer): Buffer {
  // note: secp256k1 v3 doesn't allow optional parameter
  return Buffer.from(secp256k1.ecdh(Uint8Array.from(publicKey), Uint8Array.from(privateKey), {}))
}

export const ecdhUnsafe = function(
  publicKey: Buffer,
  privateKey: Buffer,
  compressed?: boolean,
): Buffer {
  // ecdhUnsafe method is not part of secp256k1 v4 package
  // this implementation is based on v3
  // ensure valid publicKey length
  if (publicKey.length !== 33 && publicKey.length !== 65) {
    throw new RangeError('public key length is invalid')
  }

  // ensure valid privateKey length
  if (privateKey.length !== 32) {
    throw new RangeError('private key length is invalid')
  }

  return Buffer.from(
    secp256k1v3.ecdhUnsafe(Uint8Array.from(publicKey), Uint8Array.from(privateKey), compressed),
  )
}
