In order to contact Athenz Services (ZMS/ZTS) or other Athenz Enabled services,
your client needs to establish a HTTPS connection using its Athenz issued
x.509 certificate. This section contains some examples how to utilize
Athenz x.509 certificates for service authentication

## Table of Contents

* Java
    * [ZMS Client](#zms-client)
    * [ZTS Client](#zts-client)
    * [HTTPSUrlConnection Client](#httpsurlconnection-client)

## Java

In the following set of examples we're going to assume that the service
has already obtained its x.509 certificate from Athenz.

### ZMS Client

We're going to use our ZMS Java client to communicate with ZMS
running in AWS to carry out a centralized access check to see if
principal `user.john` has `read` access to `sports:nhl-scores`
resource.

First we need to update our Java project `pom.xml` file to indicate
our dependency on the ZMS Java Client and Certificate Refresh Helper
libraries

```
  <dependencies>
    <dependency>
      <groupId>com.yahoo.athenz</groupId>
      <artifactId>athenz-zms-java-client</artifactId>
      <version>VERSION-NUMBER</version>
    </dependency>
    <dependency>
      <groupId>com.yahoo.athenz</groupId>
      <artifactId>athenz-cert-refresher</artifactId>
      <version>VERSION-NUMBER</version>
    </dependency>
  </dependencies>
```

Next, let's assume the Athenz identity for the service is
`sports.api` and SIA running on this host has already generated
the private key for the service and retrieved the X.509 certificate
from ZTS Server:

    /var/lib/sia/keys/sports.api.key.pem
    /var/lib/sia/certs/sports.api.cert.pem

The ZMS server is running with a public X.509 certificate so
we're going to use the standard jdk truststore for our connection
which has a default password of `changeit`.

```java
import javax.net.ssl.SSLContext;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;

final String zmsUrl = "https://zms-address/zms/v1";
final String keyPath = "/var/lib/sia/keys/sports.api.key.pem";
final String certPath = "/var/lib/sia/certs/sports.api.cert.pem";
final String trustStorePath = javaHome + "/jre/lib/security/cacerts";
final String trustStorePassword = "changeit";

try {
    // Create our SSL Context object based on our private key and
    // certificate and jdk truststore

    KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
        certPath, keyPath);
    // Default refresh period is every hour.
    keyRefresher.startup();
    // Can be adjusted to use other values in milliseconds. However,
    // only one keyRefresher.startup call must be present.
    // keyRefresher.startup(900000);
    SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
        keyRefresher.getTrustManagerProxy());

    // create our zms client and execute request

    try (ZMSClient zmsClient = new ZMSClient(zmsUrl, sslContext)) {
        try {
            Access access = zmsClient.getAccess("read", "sports:nhl-scores", null, "user.john");
            System.out.println("Access: " + access.getGranted());
        } catch (ZMSClientException ex) {
            LOGGER.error("Unable to carry out access check: {}", ex.getMessage());
            return;
        }
    }
} catch (Exception ex) {
    LOGGER.error("Unable to process request", ex);
    return;
}
```

### ZTS Client

We're going to use our ZTS Java client to communicate with
ZTS Server running in AWS to retrieve the public key for
the `weather.api` service with key id `weather.api.key`.

First we need to update our Java project `pom.xml` file to indicate
our dependency on the ZTS Java Client and Certificate Refresh Helper
libraries

```
  <dependencies>
    <dependency>
      <groupId>com.yahoo.athenz</groupId>
      <artifactId>athenz-zts-java-client</artifactId>
      <version>VERSION-NUMBER</version>
    </dependency>
    <dependency>
      <groupId>com.yahoo.athenz</groupId>
      <artifactId>athenz-cert-refresher</artifactId>
      <version>VERSION-NUMBER</version>
    </dependency>
  </dependencies>
```

Next, let's assume the Athenz identity for the service is
`sports.api` and SIA running on this host has already generated
the private key for the service and retrieved the X.509 certificate
from ZTS Server:

    /var/lib/sia/keys/sports.api.key.pem
    /var/lib/sia/certs/sports.api.cert.pem

The ZTS server is running with a public X.509 certificate so
we're going to use the standard jdk truststore for our connection
which has a default password of `changeit`.

```java
import javax.net.ssl.SSLContext;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;

final String ztsUrl = "https://zts-address/zts/v1";
final String keyPath = "/var/lib/sia/keys/sports.api.key.pem";
final String certPath = "/var/lib/sia/certs/sports.api.cert.pem";
final String trustStorePath = javaHome + "/jre/lib/security/cacerts";
final String trustStorePassword = "changeit";

try {
    // Create our SSL Context object based on our private key and
    // certificate and jdk truststore

    KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
        certPath, keyPath);
    // Default refresh period is every hour.
    keyRefresher.startup();
    // Can be adjusted to use other values in milliseconds.
    //keyRefresher.startup(900000);
    SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
        keyRefresher.getTrustManagerProxy());

    // create our zts client and execute request

    try (ZTSClient ztsClient = new ZTSClient(ztsUrl, sslContext)) {
        try {
            PublicKeyEntry publicKey = ztsClient.getPublicKeyEntry("weather", "api", "weather.api.key");
            System.out.println("PublicKey: " + publicKey.getKey());
        } catch (ZTSClientException ex) {
            LOGGER.error("Unable to retrieve public key: {}", ex.getMessage());
            return;
        }
    }
} catch (Exception ex) {
    LOGGER.error("Unable to process request", ex);
    return;
}
```

** Important **

During the shutdown of the application, `ZTSClient.cancelPrefetch()`
must be called to stop the timer thread that automatically fetches
and refreshes any cached tokens in the ZTS Client.

### Apache HTTPClient

This example demonstrates how to correctly set up Apache HTTPClient
for mutual TLS with persistent connections and connection pooling, with
automatic certificate refreshing.

```java
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.NoopUserTokenHandler;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;

import javax.net.ssl.SSLContext;

public class Example {

    private final KeyRefresher keyRefresher;
    private final CloseableHttpClient httpClient;

    // These parameters normally point to files generated by SIA on managed hosts
    public Example(String trustStorePath, String trustStorePassword, String certPath,
        String keyPath) throws Exception {
        // Create a key refresher to automatically reload key/cert when updated by SIA
        this.keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword, certPath,
            keyPath);
        keyRefresher.startup();

        // Create TLS context
        // Note that this may create a TLS 1.3 context when supported
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
            keyRefresher.getTrustManagerProxy());

        // Create the actual HTTP client
        this.httpClient = HttpClients.custom()
            // Use the context that has our keys and trusted CAs
            .setSSLContext(sslContext)
            // Enable connection pooling - when mutual TLS used this gets disabled by default!
            .setUserTokenHandler(NoopUserTokenHandler.INSTANCE)
            // You can set more options here as desired, for example number of connections to use
            .build();
    }

    public void callSomeService(URI uri) {
        HttpResponse response = null;
        try {
            HttpGet request = new HttpGet(uri);
            response = httpClient.execute(request);
            // Do something with the response
            System.err.println("Got response: " + response.getStatusLine().getStatusCode());
        } catch (IOException e) {
            // Handle connection level errors here
            e.printStackTrace();
        } finally {
            // Ensure the entire request entity is consumed to release the connection for reuse
            // Note that calling CloseableHttpResponse.close() will make the connection ineligible
            // for reuse so it must be avoided
            if (response != null) {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        }
    }
}
```

### HTTPSUrlConnection Client

_Note: This method does not support connection pooling and is only
included as a demonstration, production code should use fully featured
HTTP client._

We're going to use a HTTPSUrlConnection client to communicate with
an HTTPS Server running to retrieve some data for a given url.

First we need to update our Java project `pom.xml` file to indicate
our dependency on the Certificate Refresh Helper library.

```
  <dependencies>
    <dependency>
      <groupId>com.yahoo.athenz</groupId>
      <artifactId>athenz-cert-refresher</artifactId>
      <version>VERSION-NUMBER</version>
    </dependency>
  </dependencies>
```

Next, let's assume the Athenz identity for the service is
`sports.api` and SIA running on this host has already generated
the private key for the service and retrieved the X.509 certificate
from ZTS Server:

    /var/lib/sia/keys/sports.api.key.pem
    /var/lib/sia/certs/sports.api.cert.pem

The HTTPS server is running with an Athenz issued certificate so our
truststore must include the Athenz CA certificates. For the following
example, the truststore containing the Athenz CA certificates will be located
at `/home/example/athenz_certificate_bundle.jks` with a default password
of `changeit`.

```java
import javax.net.ssl.SSLContext;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;

final String keyPath = "/var/lib/sia/keys/sports.api.key.pem";
final String certPath = "/var/lib/sia/certs/sports.api.cert.pem";
final String trustStorePath = "/home/example/athenz_certificate_bundle.jks";
final String trustStorePassword = "changeit";

try {
    KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
            certPath, keyPath);
    // Default refresh period is every hour.
    keyRefresher.startup();
    // Can be adjusted to use other values in milliseconds.
    //keyRefresher.startup(900000);
    SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
            keyRefresher.getTrustManagerProxy());

    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    HttpsURLConnection con = (HttpsURLConnection) new URL(url).openConnection();
    con.setReadTimeout(15000);
    con.setDoOutput(true);
    con.connect();

    try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
          sb.append(line);
        }
        System.out.println("Data output: " + sb.toString());
    }

} catch (Exception ex) {
    LOGGER.error("Unable to process request", ex);
    return;
}
```
