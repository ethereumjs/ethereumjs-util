/**
 * Re-exports commonly used modules:
 * * Adds [`ethjs-util`](https://github.com/ethjs/ethjs-util) methods.
 * * Exports [`BN`](https://github.com/indutny/bn.js), [`rlp`](https://github.com/ethereumjs/rlp).
 * @packageDocumentation
 */

/// <reference path="../typings/ethjs-util.d.ts"/>
import * as ethjsUtil from 'ethjs-util'
import * as BN from 'bn.js'
import * as rlp from 'rlp'

/**
 * [`ethjsUtil`](https://github.com/ethjs/ethjs-util)
 */
export { ethjsUtil }

/**
 * [`BN`](https://github.com/indutny/bn.js)
 */
export { BN }

/**
 * [`rlp`](https://github.com/ethereumjs/rlp)
 */
export { rlp }
