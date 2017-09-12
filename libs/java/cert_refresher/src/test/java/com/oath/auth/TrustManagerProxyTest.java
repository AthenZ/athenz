package com.oath.auth;

import mockit.Deencapsulation;
import mockit.Expectations;
import mockit.Mocked;
import org.junit.Test;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

public class TrustManagerProxyTest {

    @Test
    public void testTrustManagerProxySetTrustManger() {
        TrustManager[] trustManagers = new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustManagers);
        X509TrustManager trustManagerFirst = Deencapsulation.getField(trustManagerProxy, "trustManager");

        assertNotNull(trustManagerFirst);


        trustManagerProxy.setTrustManager(new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }});

        X509TrustManager trustManagerSecond = Deencapsulation.getField(trustManagerProxy, "trustManager");
        assertNotNull(trustManagerSecond);

        assertNotSame(trustManagerFirst, trustManagerSecond);
    }

    @Test
    public void testTrustManagerProxyCheckClientTrusted(@Mocked X509TrustManager mockedTrustManager) throws CertificateException {
        new Expectations() {{
            mockedTrustManager.checkClientTrusted((X509Certificate[]) any, "cert"); times = 1;
        }};

        TrustManager[] trustManagers = new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustManagers);

        trustManagerProxy.checkClientTrusted(null, "cert");
    }

    @Test
    public void testTrustManagerProxyCheckServerTrusted(@Mocked X509TrustManager mockedTrustManager) throws CertificateException {
        new Expectations() {{
            mockedTrustManager.checkServerTrusted((X509Certificate[]) any, "cert"); times = 1;
        }};

        TrustManager[] trustManagers = new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustManagers);

        trustManagerProxy.checkServerTrusted(null, "cert");
    }

    @Test
    public void testTrustManagerProxyGetAcceptedIssuers(@Mocked X509TrustManager mockedTrustManager) throws CertificateException {
        new Expectations() {{
            mockedTrustManager.getAcceptedIssuers(); times = 1; result = null;
        }};

        TrustManager[] trustManagers = new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};

        TrustManagerProxy trustManagerProxy = new TrustManagerProxy(trustManagers);

        assertNull(trustManagerProxy.getAcceptedIssuers());
    }

}
