import { EVMLC } from '../src';

const evmlc = new EVMLC('127.0.0.1', 8080, {
	from: '',
	gas: 10000,
	gasPrice: 0
});

const account = evmlc.accounts.create();
const encrypted = account.encrypt('danu');

console.log('ACCOUNT: ', account);
console.log('ENCRYPTED: ', encrypted);
console.log('DECRYPTED: ', evmlc.accounts.decrypt(encrypted, 'danu'));
