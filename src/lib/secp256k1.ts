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
    throw new Error('private was invalid, try again')
  }

  const point = ec.g.mul(d)
  return toPublicKey(point.getX(), point.getY(), compressed)
}

exports.privateKeyModInverse = function(privateKey: Buffer): Buffer {
  const bn = new BN(privateKey)
  if (bn.ucmp(ecparams.n) >= 0 || bn.isZero()) {
    throw new Error('private key range is invalid')
  }

  return bn.invm(ecparams.n).toBuffer()
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

  return Buffer.concat([r.toBuffer(), s.toBuffer()])
}

const toPublicKey = function(x: BN, y: BN, compressed: boolean): Buffer {
  let publicKey

  if (compressed) {
    publicKey = Buffer.alloc(33)
    publicKey[0] = y.isOdd() ? 0x03 : 0x02
    x.toBuffer().copy(publicKey, 1)
  } else {
    publicKey = Buffer.alloc(65)
    publicKey[0] = 0x04
    x.toBuffer().copy(publicKey, 1)
    y.toBuffer().copy(publicKey, 33)
  }

  return publicKey
}
