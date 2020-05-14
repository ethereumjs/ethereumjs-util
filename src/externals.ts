/**
 * Re-exports commonly used modules:
 * * Adds [`ethjs-util`](https://github.com/ethjs/ethjs-util) methods.
 * * Exports [`BN`](https://github.com/indutny/bn.js), [`rlp`](https://github.com/ethereumjs/rlp).
 * @packageDocumentation
 */

const ethjsUtil = require('ethjs-util')
import * as BN from 'bn.js'
import * as rlp from 'rlp'

/**
 * [`ethjsUtil`](https://github.com/ethjs/ethjs-util)
 */
Object.assign(exports, ethjsUtil)

/**
 * [`BN`](https://github.com/indutny/bn.js)
 */
// PatchedBN applies a temporary fix for missing `strip()` when
// a bn.js@v4 instance uses a bn.js@v5 instance:
// https://github.com/indutny/bn.js/issues/239#issuecomment-626237202
class PatchedBN extends BN {
  strip() {
    // @ts-ignore
    return this._strip()
  }
}
export { PatchedBN as BN }

/**
 * [`rlp`](https://github.com/ethereumjs/rlp)
 */
export { rlp }
