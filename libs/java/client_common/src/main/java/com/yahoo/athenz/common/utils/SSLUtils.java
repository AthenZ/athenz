package com.yahoo.athenz.common.utils;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;

public class SSLUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSLUtils.class);

    public static class ClientSSLContextBuilder {
        private final String sslProtocol;
        private PrivateKeyStore privateKeyStore;
        private char[] keyStorePassword;
        private char[] keyManagerPassword;
        private String keyStorePath;
        private String keyStoreType = "pkcs12";
        private String trustStorePath;
        private char[] trustStorePassword;
        private String trustStoreType = "pkcs12";
        private String keyStorePasswordAppName;
        private String keyManagerPasswordAppName;
        private String trustStorePasswordAppName;
        private String certAlias;
        
        public ClientSSLContextBuilder(final String sslProtocol) {
            this.sslProtocol = sslProtocol;
        }
        
        public ClientSSLContextBuilder keyStorePassword(final char[] keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
            return this;
        }
        
        public ClientSSLContextBuilder keyManagerPassword(final char[] keyManagerPassword) {
            this.keyManagerPassword = keyManagerPassword;
            return this;
        }
        
        public ClientSSLContextBuilder keyStorePath(final String keyStorePath) {
            this.keyStorePath = keyStorePath;
            return this;
        }
        
        public ClientSSLContextBuilder keyStoreType(final String keyStoreType) {
            this.keyStoreType = keyStoreType;
            return this;
        }
        
        public ClientSSLContextBuilder trustStorePath(final String trustStorePath) {
            this.trustStorePath = trustStorePath;
            return this;
        }
        
        public ClientSSLContextBuilder trustStorePassword(final char[] trustStorePassword) {
            this.trustStorePassword = trustStorePassword;
            return this;
        }
        
        public ClientSSLContextBuilder trustStoreType(final String trustStoreType) {
            this.trustStoreType = trustStoreType;
            return this;
        }
        
        public ClientSSLContextBuilder keyStorePasswordAppName(final String keyStorePasswordAppName) {
            this.keyStorePasswordAppName = keyStorePasswordAppName;
            return this;
        }
        
        public ClientSSLContextBuilder keyManagerPasswordAppName(final String keyManagerPasswordAppName) {
            this.keyManagerPasswordAppName = keyManagerPasswordAppName;
            return this;
        }
        
        public ClientSSLContextBuilder trustStorePasswordAppName(final String trustStorePasswordAppName) {
            this.trustStorePasswordAppName = trustStorePasswordAppName;
            return this;
        }
        
        public ClientSSLContextBuilder privateKeyStore(final PrivateKeyStore privateKeyStore) {
            this.privateKeyStore = privateKeyStore;
            return this;
        }
        
        public ClientSSLContextBuilder certAlias(final String certAlias) {
            this.certAlias = certAlias;
            return this;
        }
        
        public SSLContext build() {
            SSLContext context;
            KeyStore keyStore;
            KeyStore trustStore;
            KeyManagerFactory kmf;
            TrustManagerFactory tmf;
            KeyManager[] keyManagers = null;
            TrustManager[] trustManagers = null;
            
            if (keyStorePath == null && trustStorePath == null) {
                return null;
            }
            
            try {
                if (keyStorePath != null) {
                    LOGGER.info("createSSLContextObject: using SSL KeyStore path: {}", keyStorePath);
                    keyStore = loadStore(keyStorePath, keyStoreType, getPassword(keyStorePassword, privateKeyStore, keyStorePasswordAppName));
                    kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                    if (keyManagerPassword == null) {
                        throw new IllegalArgumentException("Missing key manager password for the key store: " + keyStorePath);
                    }
                    keyManagerPassword = getPassword(keyManagerPassword, privateKeyStore, keyManagerPasswordAppName);
                    kmf.init(keyStore, keyStorePassword);
                    keyManagers = getAliasedKeyManagers(kmf.getKeyManagers(), certAlias);
                }
                if (trustStorePath != null) {
                    LOGGER.info("createSSLContextObject: using SSL TrustStore path: {}", trustStorePath);
                    trustStore = loadStore(trustStorePath, trustStoreType, getPassword(trustStorePassword, privateKeyStore, trustStorePasswordAppName));
                    tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init(trustStore);
                    trustManagers = tmf.getTrustManagers();
                }
                // Initialize context
                context = SSLContext.getInstance(sslProtocol);
                context.init(keyManagers, trustManagers, null);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }

            return context;
        }
        
        private static char[] getPassword(char[] password, final PrivateKeyStore privateKeyStore, String appName) {
            if (password != null) {
                if (null != privateKeyStore) {
                    password = privateKeyStore.getSecret(appName, String.valueOf(password));
                }
            }
            return password;
        }
        
        private static KeyStore loadStore(String store, String storeType, char[] storePassword) throws Exception {
            KeyStore keystore = null;
            if (!store.isEmpty()) {
                keystore = KeyStore.getInstance(storeType);
                try (InputStream inStream = new FileInputStream(store)) {
                    keystore.load(inStream, storePassword);
                }
            }
            return keystore;
        }
        
        private static KeyManager[] getAliasedKeyManagers(KeyManager[] managers, String alias) {
            if (managers != null) {
                if (alias != null) {
                    for (int idx = 0; idx < managers.length; idx++) {
                        if (managers[idx] instanceof X509ExtendedKeyManager) {
                            managers[idx] = new ClientAliasedX509ExtendedKeyManager((X509ExtendedKeyManager) managers[idx], alias);
                        }
                    }
                }
            }
            return managers;
        }
    }
    
    static class ClientAliasedX509ExtendedKeyManager extends X509ExtendedKeyManager {
        private final String alias;
        private final X509ExtendedKeyManager delegate;

        public ClientAliasedX509ExtendedKeyManager(X509ExtendedKeyManager keyManager, String keyAlias) {
            alias = keyAlias;
            delegate = keyManager;
        }

        public X509ExtendedKeyManager getDelegate() {
            return delegate;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            if (alias == null) {
                return delegate.chooseClientAlias(keyType, issuers, socket);
            }
            return getClientAlias(keyType, issuers);
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return delegate.getClientAliases(keyType, issuers);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return delegate.getCertificateChain(alias);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return delegate.getPrivateKey(alias);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            if (alias == null) {
                return delegate.chooseEngineClientAlias(keyType, issuers, engine);
            }
            return getClientAlias(keyType, issuers);
        }

        String getClientAlias(String[] keyType, Principal[] issuers) {
            for (String kt : keyType) {
                String[] aliases = delegate.getClientAliases(kt, issuers);
                if (aliases != null) {
                    for (String a : aliases) {
                        if (alias.equals(a)) {
                            return alias;
                        }
                    }
                }
            }
            return null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            throw new UnsupportedOperationException();
        }
        
        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            throw new UnsupportedOperationException();
        }
        
        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            throw new UnsupportedOperationException();
        }
    }
    
    public static PrivateKeyStore loadServicePrivateKey(String pkeyFactoryClass) {
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).getDeclaredConstructor().newInstance();
        } catch (Exception ex) {
            LOGGER.error("Invalid PrivateKeyStoreFactory class: {}", pkeyFactoryClass, ex);
            throw new IllegalArgumentException("Invalid private key store", ex);
        }
        return pkeyFactory.create();
    }
    
}
