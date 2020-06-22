//TODO: tests
import * as secp256k1 from 'secp256k1'
import BN = require('bn.js')

const n = new BN(
  Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'),
)

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

interface SigObj {
  r: Buffer
  s: Buffer
}

export const privateKeyVerify = function(privateKey: Buffer): boolean {
  return secp256k1.privateKeyVerify(privateKey)
}

export const privateKeyExport = function(privateKey: Buffer, compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.privateKeyExport(privateKey, compressed))
}

export const privateKeyNegate = function(privateKey: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyNegate(privateKey))
}

export const privateKeyModInverse = function(privateKey: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyModInverse(privateKey))
}

export const privateKeyTweakAdd = function(privateKey: Buffer, tweak: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyTweakAdd(privateKey, tweak))
}

export const privateKeyTweakMul = function(privateKey: Buffer, tweak: Buffer): Buffer {
  return Buffer.from(secp256k1.privateKeyTweakMul(privateKey, tweak))
}

export const publicKeyCreate = function(privateKey: Buffer, compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.publicKeyCreate(privateKey, compressed))
}

export const publicKeyConvert = function(publicKey: Buffer, compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.publicKeyConvert(publicKey, compressed))
}

export const publicKeyVerify = function(publicKey: Buffer): boolean {
  return secp256k1.publicKeyVerify(publicKey)
}

export const publicKeyTweakAdd = function(
  publicKey: Buffer,
  tweak: Buffer,
  compressed?: boolean,
): Buffer {
  return Buffer.from(secp256k1.publicKeyTweakAdd(publicKey, tweak, compressed))
}

export const publicKeyTweakMul = function(
  publicKey: Buffer,
  tweak: Buffer,
  compressed?: boolean,
): Buffer {
  return Buffer.from(secp256k1.publicKeyTweakMul(publicKey, tweak, compressed))
}

export const publicKeyCombine = function(publicKeys: Buffer[], compressed?: boolean): Buffer {
  return Buffer.from(secp256k1.publicKeyCombine(publicKeys, compressed))
}

export const signatureNormalize = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureNormalize(signature))
}

export const signatureExport = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureExport(signature))
}

export const signatureImport = function(signature: Buffer): Buffer {
  return Buffer.from(secp256k1.signatureImport(signature))
}

export const signatureImportLax = function(signature: Buffer): Buffer {
  if (signature.length === 0) {
    throw new RangeError('signature length is invalid')
  }

  const sigObj = importLax(signature)
  if (sigObj === null) {
    throw new Error("couldn't parse DER signature")
  }

  let r = new BN(sigObj.r)
  if (r.ucmp(n)) {
    r = new BN(0)
  }

  let s = new BN(sigObj.s)
  if (s.ucmp(n)) {
    s = new BN(0)
  }

  return Buffer.concat([r.toBuffer(), s.toBuffer()])
}

export const sign = function(
  message: Buffer,
  privateKey: Buffer,
  options?: SignOptions,
): { signature: Buffer; recovery: number } {
  const sig = secp256k1.ecdsaSign(message, privateKey, options)

  return {
    signature: Buffer.from(sig.signature),
    recovery: sig.recid,
  }
}

export const verify = function(message: Buffer, signature: Buffer, publicKey: Buffer): boolean {
  return secp256k1.ecdsaVerify(signature, message, publicKey)
}

export const recover = function(
  signature: Buffer,
  recid: number,
  message: Buffer,
  compressed?: boolean,
): Buffer {
  return Buffer.from(secp256k1.ecdsaRecover(signature, recid, message, compressed))
}

export const ecdh = function(publicKey: Buffer, privateKey: Buffer): Buffer {
  return Buffer.from(secp256k1.ecdh(publicKey, privateKey, {}))
}

//TODO use compressed
export const ecdhUnsafe = function(
  publicKey: Buffer,
  privateKey: Buffer,
  compressed?: boolean,
): Buffer {
  const fn = function(x: Uint8Array, y: Uint8Array) {
    const pubKey = new Uint8Array(33)
    pubKey[0] = (y[31] & 1) === 0 ? 0x02 : 0x03
    pubKey.set(x, 1)
    return pubKey
  }

  return Buffer.from(secp256k1.ecdh(publicKey, privateKey, { hashfn: fn }))
}

const importLax = function(signature: Buffer): SigObj | null {
  const r = Buffer.alloc(32, 0)
  const s = Buffer.alloc(32, 0)

  const length = signature.length
  let index = 0

  // sequence tag byte
  if (signature[index++] !== 0x30) {
    return null
  }

  // sequence length byte
  let lenbyte = signature[index++]
  if (lenbyte & 0x80) {
    index += lenbyte - 0x80
    if (index > length) {
      return null
    }
  }

  // sequence tag byte for r
  if (signature[index++] !== 0x02) {
    return null
  }

  // length for r
  let rlen = signature[index++]
  if (rlen & 0x80) {
    lenbyte = rlen - 0x80
    if (index + lenbyte > length) {
      return null
    }
    for (; lenbyte > 0 && signature[index] === 0x00; index += 1, lenbyte -= 1);
    for (rlen = 0; lenbyte > 0; index += 1, lenbyte -= 1) rlen = (rlen << 8) + signature[index]
  }
  if (rlen > length - index) {
    return null
  }
  let rindex = index
  index += rlen

  // sequence tag byte for s
  if (signature[index++] !== 0x02) {
    return null
  }

  // length for s
  let slen = signature[index++]
  if (slen & 0x80) {
    lenbyte = slen - 0x80
    if (index + lenbyte > length) {
      return null
    }
    for (; lenbyte > 0 && signature[index] === 0x00; index += 1, lenbyte -= 1);
    for (slen = 0; lenbyte > 0; index += 1, lenbyte -= 1) slen = (slen << 8) + signature[index]
  }
  if (slen > length - index) {
    return null
  }
  let sindex = index
  index += slen

  // ignore leading zeros in r
  for (; rlen > 0 && signature[rindex] === 0x00; rlen -= 1, rindex += 1);
  // copy r value
  if (rlen > 32) {
    return null
  }
  const rvalue = signature.slice(rindex, rindex + rlen)
  rvalue.copy(r, 32 - rvalue.length)

  // ignore leading zeros in s
  for (; slen > 0 && signature[sindex] === 0x00; slen -= 1, sindex += 1);
  // copy s value
  if (slen > 32) {
    return null
  }
  const svalue = signature.slice(sindex, sindex + slen)
  svalue.copy(s, 32 - svalue.length)

  return { r: r, s: s }
}
