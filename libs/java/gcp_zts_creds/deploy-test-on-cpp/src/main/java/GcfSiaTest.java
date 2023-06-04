
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.creds.gcp.GCPFunctionIdentity;
import com.yahoo.athenz.creds.gcp.GCPSIACredentials;
import com.yahoo.athenz.zts.ZTSClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class GcfSiaTest implements HttpFunction {

    void getSiaCertsDemo() {
        // Read configurations.
        final String athenzDomain = getMandatoryEnvVar("ATHENZ_DOMAIN");
        final String athenzService = getMandatoryEnvVar("ATHENZ_SERVICE");
        final String gcpProjectId = getMandatoryEnvVar("GCP_PROJECT_ID");
        final String gcpRegion = getMandatoryEnvVar("GCP_REGION");
        final String athenzProvider = "sys.gcp." + gcpRegion;
        final String ztsUrl = getMandatoryEnvVar("ZTS_URL");
        final String certDn = "ou=Athenz,o=Oath"; // the dn you want included in cert - should not change
        final String certDomain = "gcp.yahoo.cloud"; // do not change

        // Generate a private key and retrieve the corresponding certificate from Athenz ZTS Service.
        GCPFunctionIdentity gcpIdentity;
        try (ZTSClient client = new ZTSClient(ztsUrl)) {
            ZTSClient.setX509CsrDetails(certDn, certDomain);
            gcpIdentity = GCPSIACredentials.getGCPFunctionServiceCertificate(
                    client,
                    athenzDomain,
                    athenzService,
                    gcpProjectId,
                    athenzProvider);
        }

        X509Certificate certificate = gcpIdentity.getX509Certificate();
        PrivateKey privateKey = gcpIdentity.getPrivateKey();

        LOG.debug("SIA CERTIFICATE:\n" + Crypto.convertToPEMFormat(certificate));
        //  LOG.debug("SIA PRIVATE-KEY:\n" + Crypto.convertToPEMFormat(privateKey));     Commented out: too sensitive
    }

    String getMandatoryEnvVar(String envVar) {
        String value = System.getenv(envVar);
        if (value == null) {
            throw new RuntimeException("Mandatory environment-variable \"" + envVar + "\" is not defined");
        }
        if (value.isEmpty()) {
            throw new RuntimeException("Mandatory environment-variable \"" + envVar + "\" is defined but is empty");
        }
        LOG.debug("Environment variable:   " + envVar + " = \"" + value + "\"");
        return value;
    }

    @Override
    public void service(HttpRequest request, HttpResponse response) throws IOException {
        BufferedWriter responseWriter = response.getWriter();
        threadLocalResponseWriter.set(responseWriter);

        try {
            getSiaCertsDemo();
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        threadLocalResponseWriter.remove();
    }

    public static ThreadLocal<BufferedWriter> threadLocalResponseWriter = new ThreadLocal<>();

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
}
