declare module 'evm-lite-lib' {
    export {default as Controller} from 'evm-lite-lib/evm/Connection';
    export {default as Account} from 'evm-lite-lib/evm/classes/Account';
    export {default as Config, ConfigSchema} from 'evm-lite-lib/tools/Config';
    export {default as Keystore} from 'evm-lite-lib/tools/Keystore';
    export {default as Database} from 'evm-lite-lib/tools/Database';
    export {default as DataDirectory} from 'evm-lite-lib/tools/DataDirectory';
    export {default as Log} from 'evm-lite-lib/tools/Log';
    export {default as Directory} from 'evm-lite-lib/tools/Directory';
}

declare module 'evm-lite-lib/evm/Connection' {
    import {BaseTX} from "evm-lite-lib/evm/utils/Interfaces";
    import Transaction from "evm-lite-lib/evm/classes/Transaction";
    import DefaultClient from "evm-lite-lib/evm/client/DefaultClient";

    interface DefaultTXOptions extends BaseTX {
        from: string;
    }

    export default class Connection extends DefaultClient {
        readonly defaultOptions: DefaultTXOptions;
        defaultFrom: string;
        defaultGas: number;
        defaultGasPrice: number;

        constructor(host: string, port: number, defaultTXOptions: DefaultTXOptions);

        prepareTransfer(to: string, value: number, from?: string): Transaction;
    }
    export {};
}

declare module 'evm-lite-lib/evm/classes/Account' {
    import {Account as Web3Account, V3JSONKeyStore} from 'web3-eth-accounts';
    import {BaseAccount, TX} from "evm-lite-lib/evm/utils/Interfaces";
    export default class Account {
        readonly address: string;
        readonly privateKey: string;
        balance: number;
        nonce: number;

        constructor(data?: Web3Account);

        static decrypt(v3JSONKeyStore: V3JSONKeyStore, password: string): Account;

        sign(message: string): any;

        signTransaction(tx: TX): any;

        encrypt(password: string): V3JSONKeyStore;

        toBaseAccount(): BaseAccount;
    }
}

declare module 'evm-lite-lib/tools/Config' {
    import Keystore from "evm-lite-lib/tools/Keystore";

    export interface ConfigSchema {
        defaults: {
            host: string;
            port: string;
            from: string;
            gas: string;
            gasprice: string;
            keystore: string;
        };
    }

    export default class Config {
        datadir: string;
        filename: string;
        data: any;
        path: string;

        constructor(datadir: string, filename: string);

        static default(datadir: string): {
            defaults: {
                from: string;
                gas: number;
                gasprice: number;
                host: string;
                keystore: string;
                port: string;
            };
        };

        static defaultTOML(datadir: string): string;

        toTOML(): string;

        read(): any;

        write(data: any): Promise<void> | undefined;

        save(): Promise<boolean>;

        getOrCreateKeystore(): Keystore;
    }
}

declare module 'evm-lite-lib/tools/Keystore' {
    import {V3JSONKeyStore} from 'web3-eth-accounts';
    import {Controller} from "evm-lite-lib/";
    import {BaseAccount} from 'evm-lite-lib/evm/utils/Interfaces';
    export default class Keystore {
        readonly path: string;

        constructor(path: string);

        static create(output: string, password: string): string;

        createWithPromise(password: string): Promise<string>;

        importV3JSONKeystore(data: string): Promise<string>;

        update(address: string, old: string, newPass: string): Promise<void>;

        files(): any[];

        all(fetch?: boolean, connection?: Controller): Promise<any[]>;

        getWithPromise(address: string): Promise<string>;

        get(address: string): V3JSONKeyStore;

        find(address: string): string;

        fetch(address: string, connection: Controller): Promise<BaseAccount>;
    }
}

declare module 'evm-lite-lib/tools/Database' {
    import {SentTX} from "evm-lite-lib/evm/utils/Interfaces";
    import Transactions from "evm-lite-lib/tools/Transactions";

    interface Schema {
        transactions: SentTX[];
    }

    export default class Database {
        readonly path: string;
        transactions: Transactions;
        readonly data: Schema;

        constructor(path: string);

        static initial(): {
            transactions: never[];
        };

        save(): Promise<boolean>;
    }
    export {};
}

declare module 'evm-lite-lib/tools/DataDirectory' {
    import Config from "evm-lite-lib/tools/Config";
    import Keystore from "evm-lite-lib/tools/Keystore";
    export default class DataDirectory {
        readonly path: string;
        readonly config: Config;
        readonly keystore: Keystore;

        constructor(path: string);

        createAndGetConfig(): Config;

        createAndGetKeystore(): Keystore;

        checkInitialisation(): Promise<void>;
    }
}

declare module 'evm-lite-lib/tools/Log' {
    export default class Log {
        readonly path: string;

        constructor(path: string);

        withCommand(command: string): this;

        append(keyword: string, description: string): this;

        show(): void;

        write(): this;
    }
}

declare module 'evm-lite-lib/tools/Directory' {
    export default class Directory {
        static exists(path: string): boolean;

        static isDirectory(path: string): boolean;

        static createDirectoryIfNotExists(path: string): void;

        static createOrReadFile(path: string, data: string): string;

        static isEquivalentObjects(objectA: any, objectB: any): boolean;
    }
}

declare module 'evm-lite-lib/evm/utils/Interfaces' {
    export interface BaseTX {
        gas: number;
        gasPrice: number;
    }

    export interface BaseAccount {
        address: string;
        nonce: number;
        balance: any;
    }

    export interface TX extends BaseTX {
        from: string;
        to?: string;
        value?: number;
        data?: string;
    }

    export interface ContractOptions {
        gas: number;
        gasPrice: number;
        from: string;
        address?: string;
        data?: string;
        jsonInterface: ABI[];
    }

    export interface Input {
        name: string;
        type: string;
    }

    export interface ABI {
        constant?: any;
        inputs: Input[];
        name?: any;
        outputs?: any[];
        payable: any;
        stateMutability: any;
        type: any;
    }

    export interface TXReceipt {
        root: string;
        transactionHash: string;
        from: string;
        to?: string;
        gasUsed: number;
        cumulativeGasUsed: number;
        contractAddress: string;
        logs: [];
        logsBloom: string;
        status: number;
    }

    export interface SentTX {
        from: string;
        to: string;
        value: number;
        gas: number;
        nonce: number;
        gasPrice: number;
        date: any;
        txHash: string;
    }
}

declare module 'evm-lite-lib/evm/classes/Transaction' {
    import {TX, TXReceipt} from "evm-lite-lib/evm/utils/Interfaces";
    import TransactionClient from "evm-lite-lib/evm/client/TransactionClient";
    export default class Transaction extends TransactionClient {
        receipt?: TXReceipt;

        constructor(tx: TX, host: string, port: number, unpackfn?: ((data: string) => any) | undefined);

        send(options?: {
            to?: string;
            from?: string;
            value?: number;
            gas?: number;
            gasPrice?: number;
        }): Promise<TXReceipt>;

        call(options?: {
            to?: string;
            from?: string;
            value?: number;
            gas?: number;
            gasPrice?: number;
        }): Promise<string>;

        toString(): string;

        from(from: string): this;

        to(to: string): this;

        value(value: number): this;

        gas(gas: number): this;

        gasPrice(gasPrice: number): this;

        data(data: string): this;
    }
}

declare module 'evm-lite-lib/evm/client/DefaultClient' {
    import {BaseAccount} from "evm-lite-lib/evm/utils/Interfaces";
    import BaseClient from "evm-lite-lib/evm/client/BaseClient";
    export default abstract class DefaultClient extends BaseClient {
        protected constructor(host: string, port: number);

        getAccount(address: string): Promise<BaseAccount | null>;

        testConnection(): Promise<boolean | null>;

        getAccounts(): Promise<BaseAccount[] | null>;

        getInfo(): Promise<object | null>;
    }
}

declare module 'evm-lite-lib/' {
    export {default as Controller} from 'evm-lite-lib/evm/Connection';
    export {default as Account} from 'evm-lite-lib/evm/classes/Account';
    export {default as Config, ConfigSchema} from 'evm-lite-lib/tools/Config';
    export {default as Keystore} from 'evm-lite-lib/tools/Keystore';
    export {default as Database} from 'evm-lite-lib/tools/Database';
    export {default as DataDirectory} from 'evm-lite-lib/tools/DataDirectory';
    export {default as Log} from 'evm-lite-lib/tools/Log';
    export {default as Directory} from 'evm-lite-lib/tools/Directory';
}

declare module 'evm-lite-lib/tools/Transactions' {
    import {SentTX} from "evm-lite-lib/evm/utils/Interfaces";
    export default class Transactions {
        constructor(dbPath: string, transactions: SentTX[]);

        all(): SentTX[];

        add(tx: any): void;

        get(hash: string): SentTX;

        sort(): void;
    }
}

declare module 'evm-lite-lib/evm/client/TransactionClient' {
    import {TXReceipt} from "evm-lite-lib/evm/utils/Interfaces";
    import BaseClient from "evm-lite-lib/evm/client/BaseClient";
    export default abstract class TransactionClient extends BaseClient {
        protected constructor(host: string, port: number);

        callTX(tx: string): Promise<string | null>;

        sendTX(tx: string): Promise<string | null>;

        sendRaw(tx: string): Promise<string | null>;

        getReceipt(txHash: string): Promise<TXReceipt | null>;
    }
}

declare module 'evm-lite-lib/evm/client/BaseClient' {
    export const request: (options: any, tx?: string | undefined) => Promise<string>;
    export default abstract class BaseClient {
        readonly host: string;
        readonly port: number;

        protected constructor(host: string, port: number);

        protected options(method: string, path: string): {
            host: string;
            port: number;
            method: string;
            path: string;
        };
    }
}

