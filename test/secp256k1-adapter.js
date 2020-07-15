// This file is imported from secp256k1 v3
// https://github.com/cryptocoinjs/secp256k1-node/blob/master/LICENSE

const assert = require('assert')
const ethUtils = require('../dist/index.js')
const BN = require('bn.js')
const util = require('./util')
const getRandomBytes = require('crypto').randomBytes

describe('privateKeyVerify', function () {
  it('should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyVerify(null)
    })
  })

  it('invalid length', function () {
    assert.equal(ethUtils.secp256k1.privateKeyVerify(util.getPrivateKey().slice(1)), false)
  })

  it('zero key', function () {
    const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
    assert.equal(ethUtils.secp256k1.privateKeyVerify(privateKey), false)
  })


  it('equal to N', function () {
    const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
    assert.equal(ethUtils.secp256k1.privateKeyVerify(privateKey), false)
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)
    privateKeys.forEach((privateKey) => {
      assert.equal(ethUtils.secp256k1.privateKeyVerify(privateKey), true)
    })
  })
})

describe('privateKeyExport', function () {
  it('private key should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyExport(null)
    })
  })

  it('private key length is invalid', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyExport(util.getPrivateKey().slice(1))
    })
  })

  it('private key is invalid', function () {
    assert.throws(function () {
      const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.privateKeyExport(privateKey)
    })
  })
})

describe('privateKeyImport', function () {
  it('should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyImport(null)
    })
  })

  it('invalid format', function () {
    const buffers = [
      Buffer.from([0x00]),
      Buffer.from([0x30, 0x7b]),
      Buffer.from([0x30, 0x87]),
      Buffer.from([0x30, 0x81]),
      Buffer.from([0x30, 0x82, 0x00, 0xff]),
      Buffer.from([0x30, 0x82, 0x00, 0x00]),
      Buffer.from([0x30, 0x82, 0x00, 0x00, 0x02, 0x01, 0x01])
    ]

    buffers.forEach((buffer) => {
      assert.throws(function () {
        ethUtils.secp256k1.privateKeyImport(buffer)
      })
    })
  })
})

describe('privateKeyExport/privateKeyImport', function () {
  it('export/import', function() {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const der1 = ethUtils.secp256k1.privateKeyExport(privateKey, true)
      const privateKey1 = ethUtils.secp256k1.privateKeyImport(der1)
      assert.deepEqual(privateKey1, privateKey)

      const der2 = ethUtils.secp256k1.privateKeyExport(privateKey, false)
      const privateKey2 = ethUtils.secp256k1.privateKeyImport(der2)
      assert.deepEqual(privateKey2, privateKey)

      const der3 = ethUtils.secp256k1.privateKeyExport(privateKey)
      const privateKey3 = ethUtils.secp256k1.privateKeyImport(der3)
      assert.deepEqual(privateKey3, privateKey)
    })
  })
})

describe('privateKeyNegate', function () {
  it('private key should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyNegate(null)
    })
  })

  it('private key length is invalid', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyNegate(util.getPrivateKey().slice(1))
    })
  })

  it('private key is 0', function () {
    const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)

    const expected = Buffer.alloc(32)
    const result = ethUtils.secp256k1.privateKeyNegate(privateKey)
    assert.deepEqual(result, expected)
  })

  it('private key equal to N', function () {
    const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)

    const expected = Buffer.alloc(32)
    const result = ethUtils.secp256k1.privateKeyNegate(privateKey)
    assert.deepEqual(result, expected)
  })

  it('private key overflow', function () {
    const privateKey = util.ec.curve.n.addn(10).toArrayLike(Buffer, 'be', 32)

    const expected = util.ec.curve.n.subn(10).toArrayLike(Buffer, 'be', 32)
    const result = ethUtils.secp256k1.privateKeyNegate(privateKey)
    assert.deepEqual(result, expected)
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)
    privateKeys.forEach((privateKey) => {
      const expected = util.ec.curve.n.sub(new BN(privateKey))
      const result = ethUtils.secp256k1.privateKeyNegate(privateKey)

      assert.deepEqual(result.toString('hex'), expected.toString(16, 64))
    })
  })
})

describe('privateKeyModInverse', function () {
  it('private key should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyModInverse(null)
    })
  })

  it('private key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey().slice(1)
      ethUtils.secp256k1.privateKeyModInverse(privateKey)
    })
  })

  it('private key is 0', function () {
    assert.throws(function () {
      const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.privateKeyModInverse(privateKey)
    })
  })

  it('private key equal to N', function () {
    assert.throws(function () {
      const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.privateKeyModInverse(privateKey)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)
    privateKeys.forEach((privateKey) => {
      const expected = new BN(privateKey).invm(new BN(util.ec.curve.n.toArrayLike(Buffer, 'be', 32)))
      const result = ethUtils.secp256k1.privateKeyModInverse(privateKey)

      assert.deepEqual(result.toString('hex'), expected.toString(16, 64))
    })
  })
})

describe('privateKeyTweakAdd', function () {
  it('private key should be a Buffer', function () {
    assert.throws(function () {
      const tweak = util.getTweak()
      ethUtils.secp256k1.privateKeyTweakAdd(null, tweak)
    })
  })

  it('private key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey().slice(1)
      const tweak = util.getTweak()
      ethUtils.secp256k1.privateKeyTweakAdd(privateKey, tweak)
    })
  })

  it('tweak should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.privateKeyTweakAdd(privateKey, null)
    })
  })

  it('tweak length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak().slice(1)
      ethUtils.secp256k1.privateKeyTweakAdd(privateKey, tweak)
    })
  })

  it('tweak overflow', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.privateKeyTweakAdd(privateKey, tweak)
    })
  })

  it('result is zero: (N - 1) + 1', function () {
    assert.throws(function () {
      const privateKey = util.ec.curve.n.sub(util.BN_ONE).toArrayLike(Buffer, 'be', 32)
      const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.privateKeyTweakAdd(privateKey, tweak)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)
    const tweak = util.getTweak()

    privateKeys.forEach((privateKey) => {
      const expected = new BN(privateKey).add(new BN(tweak)).mod(util.ec.curve.n)
      if (expected.cmp(util.BN_ZERO) === 0) {
        assert.throws(function () {
          ethUtils.secp256k1.privateKeyTweakAdd(privateKey, tweak)
        })
      } else {
        const result = ethUtils.secp256k1.privateKeyTweakAdd(privateKey, tweak)
        assert.deepEqual(result.toString('hex'), expected.toString(16, 64))
      }
    })
  })
})

describe('privateKeyTweakMul', function () {
  it('private key should be a Buffer', function () {
    assert.throws(function () {
      const tweak = util.getPrivateKey()
      ethUtils.secp256k1.privateKeyTweakMul(null, tweak)
    })
  })

  it('private key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey().slice(1)
      const tweak = util.getPrivateKey()
      ethUtils.secp256k1.privateKeyTweakMul(privateKey, tweak)
    })
  })

  it('tweak should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.privateKeyTweakMul(privateKey, null)
    })
  })

  it('tweak length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak().slice(1)
      ethUtils.secp256k1.privateKeyTweakMul(privateKey, tweak)
    })
  })

  it('tweak equal N', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.privateKeyTweakMul(privateKey, tweak)
    })
  })

  it('tweak is 0', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.privateKeyTweakMul(privateKey, tweak)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)
    const tweak = util.getTweak()

    privateKeys.forEach((privateKey) => {
      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        assert.throws(function () {
          ethUtils.secp256k1.privateKeyTweakMul(privateKey, tweak)
        })
      } else {
        const expected = new BN(privateKey).mul(new BN(tweak)).mod(util.ec.curve.n)
        const result = ethUtils.secp256k1.privateKeyTweakMul(privateKey, tweak)
        assert.deepEqual(result.toString('hex'), expected.toString(16, 64))
      }
    })
  })
})

describe('publicKeyCreate', function () {
  it('should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.publicKeyCreate(null)
    })
  })

  it('invalid length', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey().slice(1)
      ethUtils.secp256k1.publicKeyCreate(privateKey)
    })
  })

  it('overflow', function () {
    assert.throws(function () {
      const privateKey = util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.publicKeyCreate(privateKey)
    })
  })

  it('equal zero', function () {
    assert.throws(function () {
      const privateKey = new BN(0).toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.publicKeyCreate(privateKey)
    })
  })

  it('compressed should be a boolean', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.publicKeyCreate(privateKey, null)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const expected = util.getPublicKey(privateKey)

      const compressed = ethUtils.secp256k1.publicKeyCreate(privateKey, true)
      assert.deepEqual(compressed, expected.compressed)

      const uncompressed = ethUtils.secp256k1.publicKeyCreate(privateKey, false)
      assert.deepEqual(uncompressed, expected.uncompressed)
    })
  })
})

describe('publicKeyConvert', function () {
  it('should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.publicKeyConvert(null)
    })
  })

  it('length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      ethUtils.secp256k1.publicKeyConvert(publicKey)
    })
  })

  it('compressed should be a boolean', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.publicKeyConvert(publicKey, null)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const expected = util.getPublicKey(privateKey)

      const compressed = ethUtils.secp256k1.publicKeyConvert(expected.uncompressed, true)
      assert.deepEqual(compressed, expected.compressed)

      const uncompressed = ethUtils.secp256k1.publicKeyConvert(expected.uncompressed, false)
      assert.deepEqual(uncompressed, expected.uncompressed)
    })
  })
})

describe('publicKeyVerify', function () {
  it('should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.publicKeyVerify(null)
    })
  })

  it('invalid length', function () {
    const privateKey = util.getPrivateKey()
    const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('invalid first byte', function () {
    const privateKey = util.getPrivateKey()
    const publicKey = util.getPublicKey(privateKey).compressed
    publicKey[0] = 0x01
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('x overflow (first byte is 0x03)', function () {
    const publicKey = Buffer.concat([
      Buffer.from([ 0x03 ]),
      util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
    ])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('x overflow', function () {
    const publicKey = Buffer.concat([
      Buffer.from([ 0x04 ]),
      util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
    ])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('y overflow', function () {
    const publicKey = Buffer.concat([
      Buffer.from([ 0x04 ]),
      Buffer.alloc(32),
      util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
    ])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('y is even, first byte is 0x07', function () {
    const publicKey = Buffer.concat([
      Buffer.from([ 0x07 ]),
      Buffer.alloc(32),
      util.ec.curve.p.subn(1).toArrayLike(Buffer, 'be', 32)
    ])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('y**2 !== x*x*x + 7', function () {
    const publicKey = Buffer.concat([Buffer.from([0x04]), util.getTweak(), util.getTweak()])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const expected = util.getPublicKey(privateKey)

      assert.equal(ethUtils.secp256k1.publicKeyVerify(expected.uncompressed), true)
      assert.equal(ethUtils.secp256k1.publicKeyVerify(expected.uncompressed), true)
    })
  })
})

describe('publicKeyTweakAdd', function () {
  it('public key should be a Buffer', function () {
    assert.throws(function () {
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakAdd(null, tweak)
    })
  })

  it('public key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak)
    })
  })

  it('public key is invalid (version is 0x01)', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x01
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak)
    })
  })

  it('tweak should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.publicKeyTweakAdd(publicKey, null)
    })
  })

  it('tweak length length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak().slice(1)
      ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak)
    })
  })

  it('tweak overflow', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak)
    })
  })

  it('tweak produce infinity point', function () {
    // G * 1 - G = 0
    assert.throws(function () {
      const publicKey = Buffer.from(util.ec.g.encode(null, true))
      publicKey[0] = publicKey[0] ^ 0x01 // change sign of G
      const tweak = new BN(1).toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak, true)
    })
  })

  it('compressed should be a boolean', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak, null)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const tweak = util.getTweak()
      const publicPoint = util.ec.g.mul(new BN(privateKey))
      const publicKey = Buffer.from(publicPoint.encode(null, true))
      const expected = util.ec.g.mul(new BN(tweak)).add(publicPoint)

      const compressed = ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak, true)
      assert.deepEqual(compressed.toString('hex'), expected.encode('hex', true))

      const uncompressed = ethUtils.secp256k1.publicKeyTweakAdd(publicKey, tweak, false)
      assert.deepEqual(uncompressed.toString('hex'), expected.encode('hex', false))
    })
  })
})

describe('publicKeyTweakMul', function () {
  it('public key should be a Buffer', function () {
    assert.throws(function () {
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakMul(null, tweak)
    })
  })

  it('public key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak)
    })
  })

  it('public key is invalid (version is 0x01)', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x01
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak)
    })
  })

  it('tweak should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.publicKeyTweakMul(publicKey, null)
    })
  })

  it('tweak length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak().slice(1)
      ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak)
    })
  })

  it('tweak is zero', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = new BN(0).toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak)
    })
  })

  it('tweak overflow', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak)
    })
  })

  it('compressed should be a boolean', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()
      ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak, null)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const tweak = util.getTweak()
      const publicPoint = util.ec.g.mul(new BN(privateKey))
      const publicKey = Buffer.from(publicPoint.encode(null, true))
      const expected = util.ec.g.mul(new BN(tweak)).add(publicPoint)

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        assert.throws(function () {
          ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak)
        })
      } else {
        const expected = publicPoint.mul(tweak)

        const compressed = ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak, true)
        assert.deepEqual(compressed.toString('hex'), expected.encode('hex', true))

        const uncompressed = ethUtils.secp256k1.publicKeyTweakMul(publicKey, tweak, false)
        assert.deepEqual(uncompressed.toString('hex'), expected.encode('hex', false))
      }
    })
  })
})

describe('publicKeyCombine', function () {
  it('public keys should be an Array', function () {
    assert.throws(function () {
      ethUtils.secp256k1.publicKeyCombine(null)
    })
  })

  it('public keys should have length greater that zero', function () {
    assert.throws(function () {
      ethUtils.secp256k1.publicKeyCombine([])
    })
  })

  it('public key should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.publicKeyCombine([null])
    })
  })

  it('public key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      ethUtils.secp256k1.publicKeyCombine([publicKey])
    })
  })

  it('public key is invalid (version is 0x01)', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x01
      ethUtils.secp256k1.publicKeyCombine([publicKey])
    })
  })

  it('compressed should be a boolean', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.publicKeyCombine([publicKey], null)
    })
  })

  it('P + (-P) = 0', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey1 = util.getPublicKey(privateKey).compressed
      const publicKey2 = Buffer.from(publicKey1)
      publicKey2[0] = publicKey2[0] ^ 0x01
      ethUtils.secp256k1.publicKeyCombine([publicKey1, publicKey2], true)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const cnt = 1 + Math.floor(Math.random() * 3) // 1 <= cnt <= 3
      const privateKeys = []
      while (privateKeys.length < cnt) privateKeys.push(util.getPrivateKey())
      const publicKeys = privateKeys.map(function (privateKey) {
        return util.getPublicKey(privateKey).compressed
      })

      let expected = util.ec.g.mul(new BN(privateKeys[0]))
      for (let i = 1; i < privateKeys.length; ++i) {
        const publicPoint = util.ec.g.mul(new BN(privateKeys[i]))
        expected = expected.add(publicPoint)
      }

      const compressed = ethUtils.secp256k1.publicKeyCombine(publicKeys, true)
      assert.deepEqual(compressed.toString('hex'), expected.encode('hex', true))

      const uncompressed = ethUtils.secp256k1.publicKeyCombine(publicKeys, false)
      assert.deepEqual(uncompressed.toString('hex'), expected.encode('hex', false))
    })
  })
})

describe('signatureNormalize', function () {
  it('signature should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.signatureNormalize(null)
    })
  })

  it('invalid length', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey).slice(1)
      ethUtils.secp256k1.signatureNormalize(signature)
    })
  })

  it('parse fail (r equal N)', function () {
    assert.throws(function () {
      const signature = Buffer.concat([
        util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
        util.BN_ONE.toArrayLike(Buffer, 'be', 32)
      ])
      ethUtils.secp256k1.signatureNormalize(signature)
    })
  })

  it('normalize return same signature (s equal n/2)', function () {
    const signature = Buffer.concat([
      util.BN_ONE.toArrayLike(Buffer, 'be', 32),
      util.ec.nh.toArrayLike(Buffer, 'be', 32)
    ])
    const result = ethUtils.secp256k1.signatureNormalize(signature)
    assert.deepEqual(result, signature)
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const message = util.getMessage()

      const sigObj = util.sign(message, privateKey)
      const result = ethUtils.secp256k1.signatureNormalize(sigObj.signature)
      assert.deepEqual(result, sigObj.signatureLowS)
    })
  })
})

describe('signatureExport', function () {
  it('signature should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.signatureExport(null)
    })
  })

  it('invalid length', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey).slice(1)
      ethUtils.secp256k1.signatureExport(signature)
    })
  })

  it('parse fail (r equal N)', function () {
    assert.throws(function () {
      const signature = Buffer.concat([
        util.ec.n.toArrayLike(Buffer, 'be', 32),
        util.BN_ONE.toArrayLike(Buffer, 'be', 32)
      ])
      ethUtils.secp256k1.signatureExport(signature)
    })
  })

})

describe('signatureImport', function () {
  it('signature should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.signatureImport(null)
    })
  })

  it('parse fail', function () {
    assert.throws(function () {
      ethUtils.secp256k1.signatureImport(Buffer.alloc(1))
    })
  })

  it('parse not bip66 signature', function () {
    const signature = Buffer.from('308002204171936738571ff75ec0c56c010f339f1f6d510ba45ad936b0762b1b2162d8020220152670567fa3cc92a5ea1a6ead11741832f8aede5ca176f559e8a46bb858e3f6', 'hex')
    assert.throws(function () {
      ethUtils.secp256k1.signatureImport(signature)
    })
  })

})

describe('signatureImportLax', function () {
  it('signature should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.signatureImportLax(null)
    })
  })

  it('parse fail', function () {
    const buffers = [
      Buffer.alloc(0),
      Buffer.alloc(1),
      Buffer.from([0x30, 0x7b]),
      Buffer.from([0x30, 0x87]),
      Buffer.from([0x30, 0x80, 0x02, 0x80]),
      Buffer.from([0x30, 0x81, 0x00, 0x02, 0x81]),
      Buffer.from([0x30, 0x81, 0x00, 0x02, 0x81, 0x01]),
      Buffer.from([0x30, 0x82, 0x00, 0x00, 0x02, 0x01, 0x01]),
      Buffer.from([0x30, 0x81, 0x00, 0x02, 0x81, 0x01, 0x00, 0x02, 0x81]),
      Buffer.from([0x30, 0x81, 0x00, 0x02, 0x81, 0x01, 0x00, 0x02, 0x81, 0x01]),
      Buffer.from([0x30, 0x81, 0x00, 0x02, 0x21, 0x01, 0x00, 0x02, 0x81, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02]),
      Buffer.from([0x30, 0x81, 0x00, 0x02, 0x05, 0x01, 0x00, 0x02, 0x21, 0x02, 0x02, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    ]

    buffers.forEach((buffer) => {
      assert.throws(function () {
        ethUtils.secp256k1.signatureImportLax(buffer)
      })
    })
  })

  it('parse not bip66 signature', function () {
    const signature = Buffer.from('308002204171936738571ff75ec0c56c010f339f1f6d510ba45ad936b0762b1b2162d8020220152670567fa3cc92a5ea1a6ead11741832f8aede5ca176f559e8a46bb858e3f6', 'hex')
    assert.doesNotThrow(function () {
      ethUtils.secp256k1.signatureImportLax(signature)
    })
  })
})

describe('signatureExport/signatureImport', function () {
  it('signature should be a Buffer', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey) => {
      const message = util.getMessage()

      const signature = util.sign(message, privateKey).signatureLowS

      const der = ethUtils.secp256k1.signatureExport(signature)
      assert.deepEqual(ethUtils.secp256k1.signatureImport(der), signature)
      assert.deepEqual(ethUtils.secp256k1.signatureImportLax(der), signature)
    })
  })
})

describe('ecdh', function () {
  it('public key should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = null
      ethUtils.secp256k1.ecdh(publicKey, privateKey)
    })
  })

  it('public key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      ethUtils.secp256k1.ecdh(publicKey, privateKey)
    })
  })

  it('invalid public key', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x00
      ethUtils.secp256k1.ecdh(publicKey, privateKey)
    })
  })

  it('secret key should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = null
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdh(publicKey, privateKey)
    })
  })

  it('secret key invalid length', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey().slice(1)
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdh(publicKey, privateKey)
    })
  })

  it('secret key equal zero', function () {
    assert.throws(function () {
      const privateKey = util.ec.curve.zero.fromRed().toArrayLike(Buffer, 'be', 32)
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdh(publicKey, privateKey)
    })
  })

  it('secret key equal N', function () {
    assert.throws(function () {
      const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdh(publicKey, privateKey)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey1, i) => {
      const privateKey2 = util.getPrivateKey()
      const publicKey1 = util.getPublicKey(privateKey1).compressed
      const publicKey2 = util.getPublicKey(privateKey2).compressed

      const shared1 = ethUtils.secp256k1.ecdh(publicKey1, privateKey2)
      const shared2 = ethUtils.secp256k1.ecdh(publicKey2, privateKey1)
      assert.deepEqual(shared1, shared2)
    })
  })
})


describe('ecdhUnsafe', function () {
  it('public key should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = null
      ethUtils.secp256k1.ecdhUnsafe(publicKey, privateKey)
    })
  })

  it('public key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      ethUtils.secp256k1.ecdhUnsafe(publicKey, privateKey)
    })
  })

  it('invalid public key', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x00
      ethUtils.secp256k1.ecdhUnsafe(publicKey, privateKey)
    })
  })

  it('secret key should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = null
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdhUnsafe(publicKey, privateKey)
    })
  })

  it('secret key invalid length', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey().slice(1)
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdhUnsafe(publicKey, privateKey)
    })
  })

  it('secret key equal zero', function () {
    assert.throws(function () {
      const privateKey = util.ec.curve.zero.fromRed().toArrayLike(Buffer, 'be', 32)
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdhUnsafe(publicKey, privateKey)
    })
  })

  it('secret key equal N', function () {
    assert.throws(function () {
      const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      ethUtils.secp256k1.ecdhUnsafe(publicKey, privateKey)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey1, i) => {
      const privateKey2 = util.getPrivateKey()
      const publicKey1 = util.getPublicKey(privateKey1).compressed
      const publicKey2 = util.getPublicKey(privateKey2).compressed

      const shared1 = ethUtils.secp256k1.ecdhUnsafe(publicKey1, privateKey2)
      const shared2 = ethUtils.secp256k1.ecdhUnsafe(publicKey2, privateKey1)
      assert.deepEqual(shared1, shared2)
    })
  })
})

describe('sign', function () {
  it('message should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.sign(null, privateKey)
    })
  })

  it('message invalid length', function () {
    assert.throws(function () {
      const message = util.getMessage().slice(1)
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.sign(message, privateKey)
    })
  })

  it('private key should be a Buffer', function () {
    assert.throws(function () {
      const message = util.getMessage()
      ethUtils.secp256k1.sign(message, null)
    })
  })

  it('private key invalid length', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey().slice(1)
      ethUtils.secp256k1.sign(message, privateKey)
    })
  })

  it('private key is invalid', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
      ethUtils.secp256k1.sign(message, privateKey)
    })
  })

  it('options should be an Object', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.sign(message, privateKey, null)
    })
  })

  it('options.data should be a Buffer', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.sign(message, privateKey, { data: null })
    })
  })

  it('options.data length is invalid', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const data = getRandomBytes(31)
      ethUtils.secp256k1.sign(message, privateKey, { data: data })
    })
  })

  it('options.noncefn should be a Function', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.sign(message, privateKey, { noncefn: null })
    })
  })

  it('noncefn return not a Buffer', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const noncefn = function () { return null }
      ethUtils.secp256k1.sign(message, privateKey, { noncefn: noncefn })
    })
  })

  it('noncefn return Buffer with invalid length', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const noncefn = function () { return getRandomBytes(31) }
      ethUtils.secp256k1.sign(message, privateKey, { noncefn: noncefn })
    })
  })

  it('check options.noncefn arguments', function () {
    const message = util.getMessage()
    const privateKey = util.getPrivateKey()
    const data = getRandomBytes(32)
    const noncefn = function (message2, privateKey2, algo, data2, attempt) {
      assert.deepEqual(message2, message)
      assert.deepEqual(privateKey2, privateKey)
      assert.deepEqual(algo, null)
      assert.deepEqual(data2, data)
      assert.deepEqual(attempt, 0)
      return getRandomBytes(32)
    }
    ethUtils.secp256k1.sign(message, privateKey, { data: data, noncefn: noncefn })
  })

})

describe('verify', function () {
  it('message should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.verify(null, signature, publicKey)
    })
  })

  it('message length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage().slice(1)
      const signature = util.getSignature(message, privateKey)
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.verify(message, signature, publicKey)
    })
  })

  it('signature should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.verify(message, null, publicKey)
    })
  })

  it('signature length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey).slice(1)
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.verify(message, signature, publicKey)
    })
  })

  it('signature is invalid (r equal N)', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = Buffer.concat([
        util.ec.n.toArrayLike(Buffer, 'be', 32),
        getRandomBytes(32)
      ])
      const publicKey = util.getPublicKey(privateKey).compressed
      ethUtils.secp256k1.verify(message, signature, publicKey)
    })
  })

  it('public key should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)
      ethUtils.secp256k1.verify(message, signature, null)
    })
  })

  it('public key length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      ethUtils.secp256k1.verify(message, signature, publicKey)
    })
  })

  it('public key is invalid (version is 0x01)', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)
      const publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x01
      ethUtils.secp256k1.verify(message, signature, publicKey)
    })
  })

})

describe('recover', function () {
  it('message should be a Buffer', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)
      ethUtils.secp256k1.recover(null, signature, 0)
    })
  })

  it('message length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage().slice(1)
      const signature = util.getSignature(message, privateKey)
      ethUtils.secp256k1.recover(message, signature, 0)
    })
  })

  it('signature should be a Buffer', function () {
    assert.throws(function () {
      const message = util.getMessage()
      ethUtils.secp256k1.recover(message, null, 0)
    })
  })

  it('signature length is invalid', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey).slice(1)
      ethUtils.secp256k1.recover(message, signature, 0)
    })
  })

  it('signature is invalid (r equal N)', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const signature = Buffer.concat([
        util.ec.n.toArrayLike(Buffer, 'be', 32),
        getRandomBytes(32)
      ])
      ethUtils.secp256k1.recover(message, signature, 0)
    })
  })

  it('recovery should be a Number', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)
      ethUtils.secp256k1.recover(message, signature, null)
    })
  })

  it('recovery is invalid (equal 4)', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(privateKey, message)
      ethUtils.secp256k1.recover(message, signature, 4)
    })
  })

  it('compressed should be a boolean', function () {
    assert.throws(function () {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)
      ethUtils.secp256k1.recover(message, signature, 0, null)
    })
  })

  it('random tests', function () {
    const privateKeys = util.getPrivateKeys(10)

    privateKeys.forEach((privateKey, i) => {
      const message = util.getMessage()
      const publicKey = util.getPublicKey(privateKey)
      const expected = util.sign(message, privateKey)

      const sigObj = ethUtils.secp256k1.sign(message, privateKey)
      assert.deepEqual(sigObj.signature, expected.signatureLowS)
      assert.deepEqual(sigObj.recovery, expected.recovery)

      const isValid = ethUtils.secp256k1.verify(message, sigObj.signature, publicKey.compressed)
      assert.equal(isValid, true)

      const compressed = ethUtils.secp256k1.recover(message, sigObj.signature, sigObj.recovery, true)
      assert.deepEqual(compressed, publicKey.compressed)

      const uncompressed = ethUtils.secp256k1.recover(message, sigObj.signature, sigObj.recovery, false)
      assert.deepEqual(uncompressed, publicKey.uncompressed)
    })
  })
})