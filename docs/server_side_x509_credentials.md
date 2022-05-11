In order to authenticate x.509 client certificates on Athenz enabled services,
your server needs to be configured to authenticate TLS client certificates
along with updated trust store with Athenz CA certificates. This section contains
some examples how to setup your server to enable TLS client certificate authentication.

## Get Athenz CA Certificates

First, get the CA Certificates of your Athenz instances and place them in a truststore.
For our example, the truststore will be named `athenz_certificate_bundle.jks`.

You must configure your container to recognize this truststure.

If you are using other containers, you can set the SSL properties at the JVM
level via system properties.

```
-Djavax.net.ssl.trustStore=/home/example/athenz_certificate_bundle.jks
```


## Enable TLS client authentication in your container

If you are using your own application server, you would need to set
setNeedClientAuth to true. For example:

```java
SSLServerSocketFactory ssf = sc.getServerSocketFactory();
SSLServerSocket sslserversocket = (SSLServerSocket) ssf.createServerSocket(4443);
sslserversocket.setNeedClientAuth(true);
```

Please follow specific documentations provided by your
container vendor on how to require client side TLS authentication.

## Extract Certificate and Verify

If your trust store only has Athenz CA certificates, no need to extract and
verify the issuer. If not, please follow below code example for verification.

The client certificate is accessible from `jakarta.servlet.request.X509Certificate`
HttpServletRequest attribute. Here is how you can get access to the TLS certificate:

```java
import java.security.cert.X509Certificate;
import jakarta.servlet.http.HttpServletRequest;
public static final String JAVAX_CERT_ATTR = "jakarta.servlet.request.X509Certificate";

X509Certificate[] certs = (X509Certificate[]) servletRequest.getAttribute(JAVAX_CERT_ATTR);
X509Certificate x509cert = null;
if (null != certs && certs.length != 0) {
    for (X509Certificate cert: certs) {
        if (null != cert) {
            //find the first occurrence of non-null certificate
            x509cert = cert;
            break;
        }
    }
}
```

Then, validate the certificate issuers against a pre-configured set of Athenz CA
issuers.

Here is an example of how you may build the list of valid certificates from a truststore 
and then check that the issuer is valid.

```java

    private static final String DEFAULT_ISSUERS_FILE_NAME = "/home/example/athenz_certificate_bundle.jks";
    private static Set<String> X509_ISSUERS = new HashSet<>();

    X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAVAX_CERT_ATTR);
    X509Certificate x509cert = null;
    if (null != certs && certs.length != 0) {
        for (X509Certificate cert: certs) {
            if (null != cert) {
                //find the first occurrence of none null certificate
                x509cert = cert;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found x509 cert");
                }
                break;
            }
        }
    }

    if (null == x509cert) {
        // fail as x509cert is missing
        LOG.error("x509 certificate is missing");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
    }

    // validate the certificate against CAs
    X500Principal issuerx500Principal = x509cert.getIssuerX500Principal();
    String issuer = issuerx500Principal.getName();
    if (LOG.isDebugEnabled()) {
        LOG.debug("Found x509 cert issuer: {}", issuer);
    }
    if (issuer == null || issuer.isEmpty()
            || !X509_ISSUERS.contains(issuer)) {
        //fail
        LOG.error("Issuer is missing or not apart of authorized Athenz CA");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
    }

    private final void setX509CAIssuers(final String issuersFileName) {
        if (issuersFileName == null || issuersFileName.isEmpty()) {
            return;
        }
        try {
            Path path = Paths.get(issuersFileName);
            if (!path.isAbsolute()) {
                path = Paths.get(getClass().getClassLoader().getResource(issuersFileName).toURI());
            }

            KeyStore ks = null;
            try (InputStream in = new FileInputStream(path.toString())) {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(in, null);
            }
            for (Enumeration<?> e = ks.aliases(); e.hasMoreElements(); ) {
                String alias = (String)e.nextElement();
                X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
                X500Principal issuerx500Principal = cert.getIssuerX500Principal();
                String issuer = issuerx500Principal.getName();
                X509_ISSUERS.add(issuer);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("issuer: {} " , issuer);
                }
            }
        } catch (Throwable e) {
            LOG.error("Unable to set issuers from file " + issuersFileName, e);
        }
    }
```
