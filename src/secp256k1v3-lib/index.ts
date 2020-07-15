// This file is imported from secp256k1 v3
// https://github.com/cryptocoinjs/secp256k1-node/blob/master/LICENSE

import BN = require('bn.js')
const EC = require('elliptic').ec

const ec = new EC('secp256k1')
const ecparams = ec.curve

export interface SigObj {
  r: Buffer
  s: Buffer
}

exports.privateKeyExport = function(privateKey: Buffer, compressed: boolean = true): Buffer {
  const d = new BN(privateKey)
  if (d.ucmp(ecparams.n) >= 0) {
    throw new Error("couldn't export to DER format")
  }

  const point = ec.g.mul(d)
  return toPublicKey(point.getX(), point.getY(), compressed)
}

exports.privateKeyModInverse = function(privateKey: Buffer): Buffer {
  const bn = new BN(privateKey)
  if (bn.ucmp(ecparams.n) >= 0 || bn.isZero()) {
    throw new Error('private key range is invalid')
  }

  return bn.invm(ecparams.n).toArrayLike(Buffer, 'be', 32)
}

exports.signatureImport = function(sigObj: SigObj): Buffer {
  let r = new BN(sigObj.r)
  if (r.ucmp(ecparams.n) >= 0) {
    r = new BN(0)
  }

  let s = new BN(sigObj.s)
  if (s.ucmp(ecparams.n) >= 0) {
    s = new BN(0)
  }

  return Buffer.concat([r.toArrayLike(Buffer, 'be', 32), s.toArrayLike(Buffer, 'be', 32)])
}

exports.ecdhUnsafe = function(
  publicKey: Buffer,
  privateKey: Buffer,
  compressed: boolean = true,
): Buffer {
  const point = ec.keyFromPublic(publicKey)

  const scalar = new BN(privateKey)
  if (scalar.ucmp(ecparams.n) >= 0 || scalar.isZero()) {
    throw new Error('scalar was invalid (zero or overflow)')
  }

  const shared = point.pub.mul(scalar)
  return toPublicKey(shared.getX(), shared.getY(), compressed)
}

const toPublicKey = function(x: BN, y: BN, compressed: boolean): Buffer {
  let publicKey

  if (compressed) {
    publicKey = Buffer.alloc(33)
    publicKey[0] = y.isOdd() ? 0x03 : 0x02
    x.toArrayLike(Buffer, 'be', 32).copy(publicKey, 1)
  } else {
    publicKey = Buffer.alloc(65)
    publicKey[0] = 0x04
    x.toArrayLike(Buffer, 'be', 32).copy(publicKey, 1)
    y.toArrayLike(Buffer, 'be', 32).copy(publicKey, 33)
  }

  return publicKey
}
