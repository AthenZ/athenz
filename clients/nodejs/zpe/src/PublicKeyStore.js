'use strict';

let config = require('../config/config')();
const YBase64 = require('@athenz/auth-core').YBase64;
const fs = require('fs');

class PublicKeyStore {
    constructor() {
        this._ztsPublicKeyMap = {};
        this._zmsPublicKeyMap = {};

        let confFileName = config.confFileName;
        if (!confFileName) {
            let rootDir = process.env.ROOT;
            if (!rootDir) {
                rootDir = '/home/athenz';
            }
            confFileName = rootDir + '/conf/athenz/athenz.conf';
        }
        const conf = JSON.parse(fs.readFileSync(confFileName, 'utf8'));

        this._loadPublicKey(conf.zmsPublicKeys, this._zmsPublicKeyMap);
        this._loadPublicKey(conf.ztsPublicKeys, this._ztsPublicKeyMap);
    }

    static setConfig(c) {
        config = Object.assign({}, config, c.zpeClient);
    }

    _loadPublicKey(publicKeys, keyMap) {
        if (!publicKeys) {
            return;
        }

        for (let publicKey of publicKeys) {
            let id = publicKey.id,
                key = publicKey.key;

            if (!id || !key) {
                continue;
            }

            let pubKey = YBase64.ybase64Decode(key);
            keyMap[id] = pubKey;
        }
    }

    getZtsKey(keyId) {
        if (!keyId) {
            return null;
        }

        return this._ztsPublicKeyMap[keyId];
    }

    getZmsKey(keyId) {
        if (!keyId) {
            return null;
        }

        return this._zmsPublicKeyMap[keyId];
    }
}

module.exports = PublicKeyStore;
