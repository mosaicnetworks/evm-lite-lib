import { Gas, GasPrice, Value } from './types';
import { ABI } from './utils/Interfaces';
import Transaction, { BaseTX } from './classes/Transaction';
import SolidityContract from './classes/SolidityContract';
import DefaultClient from './client/DefaultClient';
interface UserDefinedDefaultTXOptions extends BaseTX {
    from: string;
}
export default class EVMLC extends DefaultClient {
    private readonly userDefaultTXOptions;
    private readonly defaultTXOptions;
    constructor(host: string, port: number, userDefaultTXOptions: UserDefinedDefaultTXOptions);
    readonly defaultOptions: UserDefinedDefaultTXOptions;
    defaultFrom: string;
    defaultGas: Gas;
    defaultGasPrice: GasPrice;
    generateContractFromABI(abi: ABI[]): SolidityContract;
    prepareTransfer(to: string, value: Value, from?: string): Promise<Transaction>;
    private requireAddress;
}
export {};