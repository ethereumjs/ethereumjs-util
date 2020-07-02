var assert = require('assert')
var ethUtils = require('../dist/index.js')
var BN = require('bn.js')
const util = require('./util')
const getRandomBytes = require('crypto').randomBytes

describe('zeros function', function () {
  it('should produce lots of 0s', function () {
    var z60 = ethUtils.zeros(30)
    var zs60 = '000000000000000000000000000000000000000000000000000000000000'
    assert.equal(z60.toString('hex'), zs60)
  })
})

describe('zero address', function () {
  it('should generate a zero address', function () {
    var zeroAddress = ethUtils.zeroAddress()
    assert.equal(zeroAddress, '0x0000000000000000000000000000000000000000')
  })
})

describe('is zero address', function () {
  it('should return true when a zero address is passed', function () {
    var isZeroAddress = ethUtils.isZeroAddress('0x0000000000000000000000000000000000000000')
    assert.equal(isZeroAddress, true)
  })

  it('should return false when the address is not equal to zero', function () {
    var nonZeroAddress = '0x2f015c60e0be116b1f0cd534704db9c92118fb6a'
    assert.equal(ethUtils.isZeroAddress(nonZeroAddress), false)
  })
})

describe('keccak', function () {
  it('should produce a keccak224 hash', function () {
    const msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    const r = '9e66938bd8f32c8610444bb524630db496bd58b689f9733182df63ba'
    const hash = ethUtils.keccak(msg, 224)
    assert.equal(hash.toString('hex'), r)
  })
  it('should produce a keccak256 hash', function () {
    const msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    const r = '82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28'
    const hash = ethUtils.keccak(msg)
    assert.equal(hash.toString('hex'), r)
  })
  it('should produce a keccak384 hash', function () {
    const msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    const r =
      '923e0f6a1c324a698139c3f3abbe88ac70bf2e7c02b26192c6124732555a32cef18e81ac91d5d97ce969745409c5bbc6'
    const hash = ethUtils.keccak(msg, 384)
    assert.equal(hash.toString('hex'), r)
  })
  it('should produce a keccak512 hash', function () {
    const msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    const r =
      '36fdacd0339307068e9ed191773a6f11f6f9f99016bd50f87fd529ab7c87e1385f2b7ef1ac257cc78a12dcb3e5804254c6a7b404a6484966b831eadc721c3d24'
    const hash = ethUtils.keccak(msg, 512)
    assert.equal(hash.toString('hex'), r)
  })
  it('should error if provided incorrect bits', function () {
    const msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    assert.throws(function () {
      ethUtils.keccak(msg, 1024)
    })
  })
})

describe('keccak256', function () {
  it('should produce a hash (keccak(a, 256) alias)', function () {
    var msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    var r = '82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28'
    var hash = ethUtils.keccak256(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('keccak without hexprefix', function () {
  it('should produce a hash', function () {
    var msg = '3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    var r = '22ae1937ff93ec72c4d46ff3e854661e3363440acd6f6e4adf8f1a8978382251'
    var hash = ethUtils.keccak(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('keccak-512', function () {
  it('should produce a hash', function () {
    var msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    var r = '36fdacd0339307068e9ed191773a6f11f6f9f99016bd50f87fd529ab7c87e1385f2b7ef1ac257cc78a12dcb3e5804254c6a7b404a6484966b831eadc721c3d24'
    var hash = ethUtils.keccak(msg, 512)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('sha256', function () {
  it('should produce a sha256', function () {
    var msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    var r = '58bbda5e10bc11a32d808e40f9da2161a64f00b5557762a161626afe19137445'
    var hash = ethUtils.sha256(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('ripemd160', function () {
  it('should produce a ripemd160', function () {
    var msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    var r = '4bb0246cbfdfddbe605a374f1187204c896fabfd'
    var hash = ethUtils.ripemd160(msg)
    assert.equal(hash.toString('hex'), r)
  })

  it('should produce a padded ripemd160', function () {
    var msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    var r = '0000000000000000000000004bb0246cbfdfddbe605a374f1187204c896fabfd'
    var hash = ethUtils.ripemd160(msg, true)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('rlphash', function () {
  it('should produce a keccak-256 hash of the rlp data', function () {
    var msg = '0x3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1'
    var r = '33f491f24abdbdbf175e812b94e7ede338d1c7f01efb68574acd279a15a39cbe'
    var hash = ethUtils.rlphash(msg)
    assert.equal(hash.toString('hex'), r)
  })
})

describe('unpad', function () {
  it('should unpad a string', function () {
    var str = '0000000006600'
    var r = ethUtils.unpad(str)
    assert.equal(r, '6600')
  })
})

describe('unpad a hex string', function () {
  it('should unpad a string', function () {
    var str = '0x0000000006600'
    var r = ethUtils.unpad(str)
    assert.equal(r, '6600')
  })
})

describe('pad', function () {
  it('should left pad a Buffer', function () {
    var buf = Buffer.from([9, 9])
    var padded = ethUtils.setLength(buf, 3)
    assert.equal(padded.toString('hex'), '000909')
  })
  it('should left truncate a Buffer', function () {
    var buf = Buffer.from([9, 0, 9])
    var padded = ethUtils.setLength(buf, 2)
    assert.equal(padded.toString('hex'), '0009')
  })
  it('should left pad a Buffer - alias', function () {
    var buf = Buffer.from([9, 9])
    var padded = ethUtils.setLengthLeft(buf, 3)
    assert.equal(padded.toString('hex'), '000909')
  })
})

describe('rpad', function () {
  it('should right pad a Buffer', function () {
    var buf = Buffer.from([9, 9])
    var padded = ethUtils.setLength(buf, 3, true)
    assert.equal(padded.toString('hex'), '090900')
  })
  it('should right truncate a Buffer', function () {
    var buf = Buffer.from([9, 0, 9])
    var padded = ethUtils.setLength(buf, 2, true)
    assert.equal(padded.toString('hex'), '0900')
  })
  it('should right pad a Buffer - alias', function () {
    var buf = Buffer.from([9, 9])
    var padded = ethUtils.setLengthRight(buf, 3)
    assert.equal(padded.toString('hex'), '090900')
  })
})

describe('bufferToHex', function () {
  it('should convert a buffer to hex', function () {
    var buf = Buffer.from('5b9ac8', 'hex')
    var hex = ethUtils.bufferToHex(buf)
    assert.equal(hex, '0x5b9ac8')
  })
  it('empty buffer', function () {
    var buf = Buffer.alloc(0)
    var hex = ethUtils.bufferToHex(buf)
    assert.strictEqual(hex, '0x')
  })
})

describe('intToHex', function () {
  it('should convert a int to hex', function () {
    var i = 6003400
    var hex = ethUtils.intToHex(i)
    assert.equal(hex, '0x5b9ac8')
  })
})

describe('intToBuffer', function () {
  it('should convert a int to a buffer', function () {
    var i = 6003400
    var buf = ethUtils.intToBuffer(i)
    assert.equal(buf.toString('hex'), '5b9ac8')
  })
})

describe('bufferToInt', function () {
  it('should convert a int to hex', function () {
    var buf = Buffer.from('5b9ac8', 'hex')
    var i = ethUtils.bufferToInt(buf)
    assert.equal(i, 6003400)
    assert.equal(ethUtils.bufferToInt(Buffer.allocUnsafe(0)), 0)
  })
  it('should convert empty input to 0', function () {
    assert.equal(ethUtils.bufferToInt(Buffer.allocUnsafe(0)), 0)
  })
})

describe('fromSigned', function () {
  it('should convert an unsigned (negative) buffer to a singed number', function () {
    var neg = '-452312848583266388373324160190187140051835877600158453279131187530910662656'
    var buf = Buffer.allocUnsafe(32).fill(0)
    buf[0] = 255

    assert.equal(ethUtils.fromSigned(buf), neg)
  })
  it('should convert an unsigned (positive) buffer to a singed number', function () {
    var neg = '452312848583266388373324160190187140051835877600158453279131187530910662656'
    var buf = Buffer.allocUnsafe(32).fill(0)
    buf[0] = 1

    assert.equal(ethUtils.fromSigned(buf), neg)
  })
})

describe('toUnsigned', function () {
  it('should convert a signed (negative) number to unsigned', function () {
    var neg = '-452312848583266388373324160190187140051835877600158453279131187530910662656'
    var hex = 'ff00000000000000000000000000000000000000000000000000000000000000'
    var num = new BN(neg)

    assert.equal(ethUtils.toUnsigned(num).toString('hex'), hex)
  })

  it('should convert a signed (positive) number to unsigned', function () {
    var neg = '452312848583266388373324160190187140051835877600158453279131187530910662656'
    var hex = '0100000000000000000000000000000000000000000000000000000000000000'
    var num = new BN(neg)

    assert.equal(ethUtils.toUnsigned(num).toString('hex'), hex)
  })
})

describe('isValidPrivate', function () {
  var SECP256K1_N = new ethUtils.BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
  it('should fail on short input', function () {
    var tmp = '0011223344'
    assert.equal(ethUtils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on too big input', function () {
    var tmp = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    assert.equal(ethUtils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (zero)', function () {
    var tmp = '0000000000000000000000000000000000000000000000000000000000000000'
    assert.equal(ethUtils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (== N)', function () {
    var tmp = SECP256K1_N.toString(16)
    assert.equal(ethUtils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should fail on invalid curve (>= N)', function () {
    var tmp = SECP256K1_N.addn(1).toString(16)
    assert.equal(ethUtils.isValidPrivate(Buffer.from(tmp, 'hex')), false)
  })
  it('should work otherwise (< N)', function () {
    var tmp = SECP256K1_N.subn(1).toString(16)
    assert.equal(ethUtils.isValidPrivate(Buffer.from(tmp, 'hex')), true)
  })
})

describe('isValidPublic', function () {
  it('should fail on too short input', function () {
    var pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey), false)
  })
  it('should fail on too big input', function () {
    var pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d00'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey), false)
  })
  it('should fail on SEC1 key', function () {
    var pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey), false)
  })
  it('shouldn\'t fail on SEC1 key with sanitize enabled', function () {
    var pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey, true), true)
  })
  it('should fail with an invalid SEC1 public key', function () {
    var pubKey = '023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey, true), false)
  })
  it('should work with compressed keys with sanitize enabled', function () {
    var pubKey = '033a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey, true), true)
  })
  it('should work with sanitize enabled', function () {
    var pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey, true), true)
  })
  it('should work otherwise', function () {
    var pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.equal(ethUtils.isValidPublic(pubKey), true)
  })
})

describe('importPublic', function () {
  var pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
  it('should work with an Ethereum public key', function () {
    var tmp = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    assert.equal(ethUtils.importPublic(Buffer.from(tmp, 'hex')).toString('hex'), pubKey)
  })
  it('should work with uncompressed SEC1 keys', function () {
    var tmp = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    assert.equal(ethUtils.importPublic(Buffer.from(tmp, 'hex')).toString('hex'), pubKey)
  })
  it('should work with compressed SEC1 keys', function () {
    var tmp = '033a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a'
    assert.equal(ethUtils.importPublic(Buffer.from(tmp, 'hex')).toString('hex'), pubKey)
  })
})

describe('publicToAddress', function () {
  it('should produce an address given a public key', function () {
    var pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    var address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    pubKey = Buffer.from(pubKey, 'hex')
    var r = ethUtils.publicToAddress(pubKey)
    assert.equal(r.toString('hex'), address)
  })
  it('should produce an address given a SEC1 public key', function () {
    var pubKey = '043a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    var address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    pubKey = Buffer.from(pubKey, 'hex')
    var r = ethUtils.publicToAddress(pubKey, true)
    assert.equal(r.toString('hex'), address)
  })
  it('shouldn\'t produce an address given an invalid SEC1 public key', function () {
    var pubKey = '023a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.throws(function () {
      ethUtils.publicToAddress(pubKey, true)
    })
  })
  it('shouldn\'t produce an address given an invalid public key', function () {
    var pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae744'
    pubKey = Buffer.from(pubKey, 'hex')
    assert.throws(function () {
      ethUtils.publicToAddress(pubKey)
    })
  })
})

describe('publicToAddress 0x', function () {
  it('should produce an address given a public key', function () {
    var pubKey = '0x3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    var address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    var r = ethUtils.publicToAddress(pubKey)
    assert.equal(r.toString('hex'), address)
  })
})

describe('privateToPublic', function () {
  it('should produce a public key given a private key', function () {
    var pubKey = '3a443d8381a6798a70c6ff9304bdc8cb0163c23211d11628fae52ef9e0dca11a001cf066d56a8156fc201cd5df8a36ef694eecd258903fca7086c1fae7441e1d'
    var privateKey = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28, 95])
    var r = ethUtils.privateToPublic(privateKey).toString('hex')
    assert.equal(r.toString('hex'), pubKey)
  })
  it('shouldn\'t produce a public key given an invalid private key', function () {
    var privateKey1 = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28, 95, 42])
    var privateKey2 = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28])
    assert.throws(function () {
      ethUtils.privateToPublic(privateKey1)
    })
    assert.throws(function () {
      ethUtils.privateToPublic(privateKey2)
    })
  })
})

describe('privateToAddress', function () {
  it('should produce an address given a private key', function () {
    var address = '2f015c60e0be116b1f0cd534704db9c92118fb6a'
    // Our private key
    var privateKey = Buffer.from([234, 84, 189, 197, 45, 22, 63, 136, 201, 58, 176, 97, 87, 130, 207, 113, 138, 46, 251, 158, 81, 167, 152, 154, 171, 27, 8, 6, 126, 156, 28, 95])
    var r = ethUtils.privateToAddress(privateKey).toString('hex')
    assert.equal(r.toString('hex'), address)
  })
})

describe('generateAddress', function () {
  it('should produce an address given a public key', function () {
    var add = ethUtils.generateAddress('990ccf8a0de58091c028d6ff76bb235ee67c1c39', 14).toString('hex')
    assert.equal(add.toString('hex'), '936a4295d8d74e310c0c95f0a63e53737b998d12')
  })
})

describe('generateAddress with hex prefix', function () {
  it('should produce an address given a public key', function () {
    var add = ethUtils.generateAddress('0x990ccf8a0de58091c028d6ff76bb235ee67c1c39', 14).toString('hex')
    assert.equal(add.toString('hex'), 'd658a4b8247c14868f3c512fa5cbb6e458e4a989')
  })
})

describe('generateAddress with nonce 0 (special case)', function () {
  it('should produce an address given a public key', function () {
    var add = ethUtils.generateAddress('0x990ccf8a0de58091c028d6ff76bb235ee67c1c39', 0).toString('hex')
    assert.equal(add.toString('hex'), 'bfa69ba91385206bfdd2d8b9c1a5d6c10097a85b')
  })
})

describe('hex prefix', function () {
  var string = 'd658a4b8247c14868f3c512fa5cbb6e458e4a989'
  it('should add', function () {
    assert.equal(ethUtils.addHexPrefix(string), '0x' + string)
  })
  it('should return on non-string input', function () {
    assert.equal(ethUtils.addHexPrefix(1), 1)
  })
})

describe('isPrecompiled', function () {
  it('should return true', function () {
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000001'), true)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000002'), true)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000003'), true)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000004'), true)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000005'), true)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000006'), true)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000007'), true)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000008'), true)
    assert.equal(ethUtils.isPrecompiled(Buffer.from('0000000000000000000000000000000000000001', 'hex')), true)
  })
  it('should return false', function () {
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000000'), false)
    assert.equal(ethUtils.isPrecompiled('0000000000000000000000000000000000000009'), false)
    assert.equal(ethUtils.isPrecompiled('1000000000000000000000000000000000000000'), false)
    assert.equal(ethUtils.isPrecompiled(Buffer.from('0000000000000000000000000000000000000000', 'hex')), false)
  })
})

describe('toBuffer', function () {
  it('should work', function () {
    // Buffer
    assert.deepEqual(ethUtils.toBuffer(Buffer.allocUnsafe(0)), Buffer.allocUnsafe(0))
    // Array
    assert.deepEqual(ethUtils.toBuffer([]), Buffer.allocUnsafe(0))
    // String
    assert.deepEqual(ethUtils.toBuffer('11'), Buffer.from([49, 49]))
    assert.deepEqual(ethUtils.toBuffer('0x11'), Buffer.from([17]))
    assert.deepEqual(ethUtils.toBuffer('1234').toString('hex'), '31323334')
    assert.deepEqual(ethUtils.toBuffer('0x1234').toString('hex'), '1234')
    // Number
    assert.deepEqual(ethUtils.toBuffer(1), Buffer.from([1]))
    // null
    assert.deepEqual(ethUtils.toBuffer(null), Buffer.allocUnsafe(0))
    // undefined
    assert.deepEqual(ethUtils.toBuffer(), Buffer.allocUnsafe(0))
    // 'toBN'
    assert.deepEqual(ethUtils.toBuffer(new BN(1)), Buffer.from([1]))
    // 'toArray'
    assert.deepEqual(ethUtils.toBuffer({
      toArray: function () {
        return [1]
      }
    }), Buffer.from([1]))
  })
  it('should fail', function () {
    assert.throws(function () {
      ethUtils.toBuffer({test: 1})
    })
  })
})

describe('baToJSON', function () {
  it('should turn a array of buffers into a pure json object', function () {
    var ba = [Buffer.from([0]), Buffer.from([1]), [Buffer.from([2])]]
    assert.deepEqual(ethUtils.baToJSON(ba), ['0x00', '0x01', ['0x02']])
  })
  it('should turn a buffers into string', function () {
    assert.deepEqual(ethUtils.baToJSON(Buffer.from([0])), '0x00')
  })
})

var echash = Buffer.from('82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28', 'hex')
var ecprivkey = Buffer.from('3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1', 'hex')

describe('ecsign', function () {
  it('should produce a signature', function () {
    var sig = ethUtils.ecsign(echash, ecprivkey)
    assert.deepEqual(sig.r, Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex'))
    assert.deepEqual(sig.s, Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex'))
    assert.equal(sig.v, 27)
  })
})

describe('ecrecover', function () {
  it('should recover a public key', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    var pubkey = ethUtils.ecrecover(echash, 27, r, s)
    assert.deepEqual(pubkey, ethUtils.privateToPublic(ecprivkey))
  })
  it('should fail on an invalid signature (v = 21)', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.throws(function () {
      ethUtils.ecrecover(echash, 21, r, s)
    })
  })
  it('should fail on an invalid signature (v = 29)', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.throws(function () {
      ethUtils.ecrecover(echash, 29, r, s)
    })
  })
  it('should fail when s is 0 bytes', function () {
    const r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    const s = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')

    const v = 27
    assert.equal(ethUtils.isValidSignature(v, r, s, true), false)
  })
  it('should fail on an invalid signature (swapped points)', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.throws(function () {
      ethUtils.ecrecover(echash, 27, s, r)
    })
  })
})

describe('hashPersonalMessage', function () {
  it('should produce a deterministic hash', function () {
    var h = ethUtils.hashPersonalMessage(Buffer.from('Hello world'))
    assert.deepEqual(h, Buffer.from('8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede', 'hex'))
  })
})

describe('isValidSignature', function () {
  it('should fail on an invalid signature (shorter r))', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1ab', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(ethUtils.isValidSignature(27, r, s), false)
  })
  it('should fail on an invalid signature (shorter s))', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca', 'hex')
    assert.equal(ethUtils.isValidSignature(27, r, s), false)
  })
  it('should fail on an invalid signature (v = 21)', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(ethUtils.isValidSignature(21, r, s), false)
  })
  it('should fail on an invalid signature (v = 29)', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(ethUtils.isValidSignature(29, r, s), false)
  })
  it('should work otherwise', function () {
    var r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
    var s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')
    assert.equal(ethUtils.isValidSignature(27, r, s), true)
  })
  // FIXME: add homestead test
})

var checksumAddresses = [
  // All caps
  '0x52908400098527886E0F7030069857D2E4169EE7',
  '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
  // All Lower
  '0xde709f2102306220921060314715629080e2fb77',
  '0x27b1fdb04752bbc536007a920d24acb045561c26',
  // Normal
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
]

describe('.toChecksumAddress()', function () {
  it('should work', function () {
    for (var i = 0; i < checksumAddresses.length; i++) {
      var tmp = checksumAddresses[i]
      assert.equal(ethUtils.toChecksumAddress(tmp.toLowerCase()), tmp)
    }
  })
})

describe('.isValidChecksumAddress()', function () {
  it('should return true', function () {
    for (var i = 0; i < checksumAddresses.length; i++) {
      assert.equal(ethUtils.isValidChecksumAddress(checksumAddresses[i]), true)
    }
  })
  it('should validate', function () {
    assert.equal(ethUtils.isValidChecksumAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6a'), false)
  })
})

describe('.isValidAddress()', function () {
  it('should return true', function () {
    assert.equal(ethUtils.isValidAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6a'), true)
    assert.equal(ethUtils.isValidAddress('0x52908400098527886E0F7030069857D2E4169EE7'), true)
  })
  it('should return false', function () {
    assert.equal(ethUtils.isValidAddress('2f015c60e0be116b1f0cd534704db9c92118fb6a'), false)
    assert.equal(ethUtils.isValidAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6'), false)
    assert.equal(ethUtils.isValidAddress('0x2f015c60e0be116b1f0cd534704db9c92118fb6aa'), false)
    assert.equal(ethUtils.isValidAddress('0X52908400098527886E0F7030069857D2E4169EE7'), false)
    assert.equal(ethUtils.isValidAddress('x2f015c60e0be116b1f0cd534704db9c92118fb6a'), false)
  })
})

describe('message sig', function () {
  const r = Buffer.from('99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
  const s = Buffer.from('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', 'hex')

  it('should return hex strings that the RPC can use', function () {
    assert.equal(ethUtils.toRpcSig(27, r, s), '0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca6600')
    assert.deepEqual(ethUtils.fromRpcSig('0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca6600'), {
      v: 27,
      r: r,
      s: s
    })
  })

  it('should throw on invalid length', function () {
    assert.throws(function () {
      ethUtils.fromRpcSig('')
    })
    assert.throws(function () {
      ethUtils.fromRpcSig('0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca660042')
    })
  })

  it('pad short r and s values', function () {
    assert.equal(ethUtils.toRpcSig(27, r.slice(20), s.slice(20)), '0x00000000000000000000000000000000000000004a1579cf389ef88b20a1abe90000000000000000000000000000000000000000326fa689f228040429e3ca6600')
  })

  it('should throw on invalid v value', function () {
    assert.throws(function () {
      ethUtils.toRpcSig(1, r, s)
    })
  })
})

describe('privateKeyVerify', function () {
  it('should be a Buffer', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyVerify(null)
    })
  })

  it('invalid length', function () {
    assert.throws(function () {
      ethUtils.secp256k1.privateKeyVerify(util.getPrivateKey().slice(1))
    })
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
  it('export/import', function () {
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
      Buffer.from([0x03]),
      util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
    ])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('x overflow', function () {
    const publicKey = Buffer.concat([
      Buffer.from([0x04]),
      util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
    ])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('y overflow', function () {
    const publicKey = Buffer.concat([
      Buffer.from([0x04]),
      Buffer.alloc(32),
      util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
    ])
    assert.equal(ethUtils.secp256k1.publicKeyVerify(publicKey), false)
  })

  it('y is even, first byte is 0x07', function () {
    const publicKey = Buffer.concat([
      Buffer.from([0x07]),
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
      ethUtils.secp256k1.sign(message, privateKey, {data: null})
    })
  })

  it('options.data length is invalid', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const data = getRandomBytes(31)
      ethUtils.secp256k1.sign(message, privateKey, {data: data})
    })
  })

  it('options.noncefn should be a Function', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      ethUtils.secp256k1.sign(message, privateKey, {noncefn: null})
    })
  })

  it('noncefn return not a Buffer', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const noncefn = function () {
        return null
      }
      ethUtils.secp256k1.sign(message, privateKey, {noncefn: noncefn})
    })
  })

  it('noncefn return Buffer with invalid length', function () {
    assert.throws(function () {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const noncefn = function () {
        return getRandomBytes(31)
      }
      ethUtils.secp256k1.sign(message, privateKey, {noncefn: noncefn})
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
    ethUtils.secp256k1.sign(message, privateKey, {data: data, noncefn: noncefn})
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
