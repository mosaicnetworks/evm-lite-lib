// @ts-ignore
import * as EthLibAccount from 'eth-lib/lib/account';

// TODO: Create typings for these modules
const scryptsy = require('scryptsy');
const keccak256 = require('keccak256');

// @ts-ignore
import { createDecipheriv } from 'browserify-cipher';

import { Defaults } from '../EVMLC';
import { V3JSONKeyStore } from './Account';

import AccountClient from '../../clients/AccountClient';
import EVM from '../../types';
import Transaction from '../transaction/Transaction';
import Account from './Account';

export default class Accounts extends AccountClient {
	private static fromPrivateKey(privateKey: string) {
		return new Account(EthLibAccount.fromPrivate(privateKey));
	}

	private static decryptAccount(json: V3JSONKeyStore, password: string) {
		if (!password) {
			throw new Error('No password given.');
		}

		if (json.version !== 3) {
			throw new Error('Not a valid V3 wallet');
		}

		let derivedKey;
		let kdfparams;
		if (json.crypto.kdf === 'scrypt') {
			kdfparams = json.crypto.kdfparams;

			derivedKey = scryptsy(
				Buffer.from(password),
				Buffer.from(kdfparams.salt, 'hex'),
				kdfparams.n,
				kdfparams.r,
				kdfparams.p,
				kdfparams.dklen
			);
		} else {
			throw new Error('Unsupported key derivation scheme');
		}

		const ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');

		const mac = keccak256(
			Buffer.concat([derivedKey.slice(16, 32), ciphertext])
		).toString('hex');

		if (mac !== json.crypto.mac) {
			throw new Error('Key derivation failed - possibly wrong password');
		}

		const decipher = createDecipheriv(
			json.crypto.cipher,
			derivedKey.slice(0, 16),
			Buffer.from(json.crypto.cipherparams.iv, 'hex')
		);
		const seed = `0x${Buffer.concat([
			decipher.update(ciphertext),
			decipher.final()
		]).toString('hex')}`;

		return Accounts.fromPrivateKey(seed);
	}

	/**
	 * The root cotnroller class for interacting with accounts.
	 *
	 * @param host - The host of the active node.
	 * @param port - The port of the HTTP service.
	 * @param defaults - The default options for accounts
	 */
	constructor(host: string, port: number, public defaults: Defaults) {
		super(host, port);
	}

	/**
	 * Should decrypt an encrypted account.
	 *
	 * @remarks
	 * A decrypted account will have access to the `sign()`, `privateKey` and
	 * `signTransaction()` attribute. Allowing to sign transactions.
	 *
	 * ```typescript
	 * const keystore = evmlc.accounts.create().encrypt('password');
	 * const decrypted = evmlc.accounts.decrypt(keystore, 'password');
	 * ```
	 *
	 * @param v3JSONKeyStore - The `v3` JSON keystore of the encrypted address.
	 * @param password - The password used to encrypt to the keystore.
	 */
	public decrypt(v3JSONKeyStore: V3JSONKeyStore, password: string) {
		return Accounts.decryptAccount(v3JSONKeyStore, password);
	}

	/**
	 * Should create a new `Account` object.
	 *
	 * @remarks
	 * ```typescript
	 * const account = evmlc.accounts.create();
	 * ```
	 *
	 * @param entropy - The entropy of the accounts address.
	 */
	public create(entropy?: string): Account {
		const randomHex = require('crypto-random-hex');

		return new Account(EthLibAccount.create(entropy || randomHex(32)));
	}

	/**
	 * Should prepare a transaction to transfer `value` to the specified `to`
	 * address.
	 *
	 * @remarks
	 * This function will not fetch nonce from the node. The example shows
	 * how to make a trnasfer of 200 tokens.
	 *
	 * ```typescript
	 * const transfer = async () {
	 *     const transaction = evmlc.prepareTransfer('TO_ADDRESS', 200);
	 *     await transaction.submit(evmlc.accounts.create())
	 * }
	 * ```
	 *
	 * @param to - The address to transfer funds to.
	 * @param value - The amount to transfer.
	 * @param from - Overrides `from` address set in the constructor.
	 */
	public prepareTransfer(
		to: EVM.Address,
		value: EVM.Value,
		from?: EVM.Address
	): Transaction {
		const _from = (from || this.defaults.from).trim();

		if (!_from) {
			throw new Error(
				'Default `from` address cannot be left blank or empty.'
			);
		}

		if (!to) {
			throw new Error('Must provide a `to` address!');
		}

		if (value <= 0) {
			throw new Error(
				'A transfer of funds must have a `value` greater than 0.'
			);
		}

		return new Transaction(
			{
				from: _from,
				to: to.trim(),
				value,
				gas: this.defaults.gas,
				gasPrice: this.defaults.gasPrice
			},
			this.host,
			this.port,
			false
		);
	}
}
