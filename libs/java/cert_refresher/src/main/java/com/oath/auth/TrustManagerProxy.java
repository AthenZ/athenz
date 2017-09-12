package com.oath.auth;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * This class creates a key manager that wraps the existing X509TrustManager.  The goal is that it watches
 * the 'key' files and when they are updated, it upates the TrustManager under the covers.  This may
 * cause connections that are in the middle of a handshake to fail, but must NOT cause any already
 * established connections to fail.  This allow the changing of the SSL context on the fly without creating
 * new server / httpClient objects
 */
public class TrustManagerProxy implements X509TrustManager {

    private volatile X509TrustManager trustManager;

    public TrustManagerProxy(TrustManager[] trustManagers) {
        this.setTrustManager(trustManagers);
    }

    /**
     * overwrites the existing key manager.
     * @param trustManagers only the first element will be used, and MUST be a X509TrustManager
     */
    public void setTrustManager(final TrustManager[] trustManagers) {
        trustManager = (X509TrustManager) trustManagers[0];
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        trustManager.checkClientTrusted(x509Certificates, s);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        trustManager.checkServerTrusted(x509Certificates, s);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }
}
