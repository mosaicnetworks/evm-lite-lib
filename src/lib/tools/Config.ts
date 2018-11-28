import * as fs from 'fs';
import * as mkdir from 'mkdirp';
import * as path from "path";
import * as toml from "toml";
import * as tomlify from 'tomlify-j0.4';

import DataDirectory from "./DataDirectory";
import Keystore from "./Keystore";


export default class Config {

    public static default(datadir: string) {
        return {
            defaults: {
                from: '',
                gas: 100000,
                gasprice: 0,
                host: '127.0.0.1',
                keystore: path.join(datadir, 'keystore'),
                port: '8080',
            }
        }
    }

    public static defaultTOML(datadir: string) {
        return tomlify.toToml(Config.default(datadir), {spaces: 2});
    }

    public data: any;
    public path: string;
    private initialData: any;

    constructor(public datadir: string, public filename: string) {
        this.data = Config.default(this.datadir);
        this.initialData = Config.default(this.datadir);

        this.path = path.join(datadir, filename);

        if (DataDirectory.exists(this.path)) {
            const tomlData: string = fs.readFileSync(this.path, 'utf8');

            this.data = toml.parse(tomlData);
            this.initialData = toml.parse(tomlData);
        }
    }

    public toTOML(): string {
        return tomlify.toToml(this.data, {spaces: 2})
    }

    public read(): any {
        if (DataDirectory.exists(this.path)) {
            return new Promise<any>((resolve, reject) => {
                fs.readFile(this.path, (err, data) => {
                    if (err) {
                        reject(err);
                        return;
                    }

                    resolve(toml.parse(data.toString()));
                });
            });
        }
    }

    public write(data: any) {
        if (DataDirectory.exists(this.path)) {
            return new Promise<void>((resolve, reject) => {
                fs.writeFile(this.path, tomlify.toToml(data), (err) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    resolve();
                })
            });
        }
    }

    public async save(): Promise<boolean> {
        return new Promise<boolean>((resolve) => {
            if (DataDirectory.isEquivalentObjects(this.data, this.initialData)) {
                resolve(false);
            } else {
                const list = this.path.split('/');
                list.pop();

                const configFileDir = list.join('/');

                if (!DataDirectory.exists(configFileDir)) {
                    mkdir.mkdirp(configFileDir);
                }

                fs.writeFile(this.path, this.toTOML(), (err) => {
                    if (!err) {
                        this.initialData = toml.parse(this.toTOML());
                    }


                    resolve(!err);
                });

            }
        });
    }

    public getOrCreateKeystore(): Keystore {
        DataDirectory.createDirectoryIfNotExists(this.data.defaults.keystore);
        return new Keystore(this.data.defaults.keystore);
    }

}