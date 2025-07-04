/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const tls = require('tls');
const { constants } = require('crypto');
const debug = require('debug')('AthenzUI:server:sslReloader');
const fs = require('fs').promises;

class SSLReloader {
    constructor(config, secrets, expressApp) {
        this.config = config;
        this.secrets = secrets;
        this.expressApp = expressApp;
        this.server = null;
        this.lastCertHash = null;
        this.lastKeyHash = null;
        this.reloadInterval =
            (config.ssl && config.ssl.reloadIntervalMs) || 12 * 60 * 60 * 1000; // Default to 12 hours
        this.isReloading = false;
        this.currentSecureContext = null;
    }

    /**
     * Initialize the SSL reloader and start monitoring
     */
    initialize(server) {
        this.server = server;

        // Always initialize the secure context with the certs loaded at startup.
        this.currentSecureContext = tls.createSecureContext({
            cert: this.secrets.serverCert,
            key: this.secrets.serverKey,
            secureOptions:
                constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1,
            ciphers: this.config.serverCipherSuites,
        });

        if (!this.config.ssl || !this.config.ssl.reloadEnabled) {
            debug('SSL auto-reloading is disabled by config.');
            return;
        }

        // If enabled, proceed with setting up the reloader.
        this.lastCertHash = this.hashContent(this.secrets.serverCert);
        this.lastKeyHash = this.hashContent(this.secrets.serverKey);

        debug(
            'SSL Reloader initialized with cert hash: %s, key hash: %s',
            this.lastCertHash,
            this.lastKeyHash
        );

        // Start monitoring for certificate changes
        this.startMonitoring();
    }

    /**
     * Start monitoring for SSL certificate changes
     */
    startMonitoring() {
        debug(
            'Starting SSL certificate monitoring (checking every %d minutes)',
            this.reloadInterval / 60000
        );

        setInterval(async () => {
            if (this.isReloading) {
                debug('SSL reload already in progress, skipping check');
                return;
            }

            try {
                await this.checkAndReloadCertificates();
            } catch (error) {
                debug('Error during certificate check: %o', error);
            }
        }, this.reloadInterval);
    }

    /**
     * Check if certificates have changed and reload if necessary
     */
    async checkAndReloadCertificates() {
        debug('Checking for SSL certificate updates...');

        try {
            const newSecrets = await this.fetchLatestCertificates();

            const newCertHash = this.hashContent(newSecrets.serverCert);
            const newKeyHash = this.hashContent(newSecrets.serverKey);

            if (
                newCertHash !== this.lastCertHash ||
                newKeyHash !== this.lastKeyHash
            ) {
                debug(
                    'SSL certificate changes detected. Old cert hash: %s, new cert hash: %s, Old key hash: %s, new key hash: %s',
                    this.lastCertHash,
                    newCertHash,
                    this.lastKeyHash,
                    newKeyHash
                );

                await this.reloadSSLContext(
                    newSecrets.serverCert,
                    newSecrets.serverKey
                );

                this.lastCertHash = newCertHash;
                this.lastKeyHash = newKeyHash;

                debug('SSL certificates successfully reloaded');
            } else {
                debug('No SSL certificate changes detected');
            }
        } catch (error) {
            debug('Failed to check/reload SSL certificates: %o', error);
            throw error;
        }
    }

    /**
     * Fetch the latest certificates from S3 or other source
     */
    async fetchLatestCertificates() {
        const newSecrets = {};

        // Fetch from file
        const certPromise = fs.readFile(this.config.serverCertPath, 'utf8');
        const keyPromise = fs.readFile(this.config.serverKeyPath, 'utf8');

        const [serverCert, serverKey] = await Promise.all([
            certPromise,
            keyPromise,
        ]);
        newSecrets.serverCert = serverCert.trim();
        newSecrets.serverKey = serverKey.trim();

        return newSecrets;
    }

    /**
     * Reload the SSL context without restarting the server
     */
    async reloadSSLContext(newCert, newKey) {
        if (this.isReloading) {
            debug('SSL reload already in progress');
            return;
        }

        this.isReloading = true;

        try {
            debug('Starting SSL context reload...');

            // Update the secrets object first
            this.secrets.serverCert = newCert;
            this.secrets.serverKey = newKey;

            // Create new SSL context
            this.currentSecureContext = tls.createSecureContext({
                cert: newCert,
                key: newKey,
                secureOptions:
                    constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1,
                ciphers: this.config.serverCipherSuites,
            });

            debug(
                'SSL context updated successfully - new connections will use updated certificates'
            );
        } catch (error) {
            debug('Failed to reload SSL context: %o', error);
            throw error;
        } finally {
            this.isReloading = false;
        }
    }

    /**
     * Get the current secure context (used by SNI callback)
     */
    getSecureContext(servername, callback) {
        debug('SNI callback requested for servername: %s', servername);
        if (this.currentSecureContext) {
            callback(null, this.currentSecureContext);
        } else {
            // Fallback to default context
            const defaultContext = tls.createSecureContext({
                cert: this.secrets.serverCert,
                key: this.secrets.serverKey,
                secureOptions:
                    constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1,
                ciphers: this.config.serverCipherSuites,
            });
            callback(null, defaultContext);
        }
    }

    /**
     * Generate a simple hash of content for comparison
     */
    hashContent(content) {
        const crypto = require('crypto');
        return crypto
            .createHash('sha256')
            .update(content)
            .digest('hex')
            .substring(0, 16);
    }
}

module.exports = SSLReloader;
