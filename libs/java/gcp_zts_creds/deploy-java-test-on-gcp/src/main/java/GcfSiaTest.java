
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
        LOG.debug("This is JAVA GCF test");

        // Read configurations.
        final String athenzDomain = getMandatoryEnvVar("ATHENZ_DOMAIN");
        final String athenzService = getMandatoryEnvVar("ATHENZ_SERVICE");
        final String gcpProjectId = getMandatoryEnvVar("GCP_PROJECT_ID");
        final String gcpRegion = getMandatoryEnvVar("GCP_REGION");
        final String athenzProvider = "sys.gcp." + gcpRegion;
        final String ztsUrl = getMandatoryEnvVar("ZTS_URL");
        final String certDomain = getMandatoryEnvVar("CERT_DOMAIN");

        // Build the certificate's Subject fields - as a single string.
        // At the end, certDn would look something like this:    "c=US, s=CA, ou=Eng"
        String certDn = "";
        if (!getOptionalEnvVar("CSR_COUNTRY").isEmpty()) {
            certDn += "c=" + getOptionalEnvVar("CSR_COUNTRY") + ", ";
        }
        if (!getOptionalEnvVar("CSR_STATE").isEmpty()) {
            certDn += "s=" + getOptionalEnvVar("CSR_STATE") + ", ";
        }
        if (!getOptionalEnvVar("CSR_LOCALITY").isEmpty()) {
            certDn += "l=" + getOptionalEnvVar("CSR_LOCALITY") + ", ";
        }
        if (!getOptionalEnvVar("CSR_ORGANIZATION").isEmpty()) {
            certDn += "o=" + getOptionalEnvVar("CSR_ORGANIZATION") + ", ";
        }
        if (!getOptionalEnvVar("CSR_ORGANIZATION_UNIT").isEmpty()) {
            certDn += "ou=" + getOptionalEnvVar("CSR_ORGANIZATION_UNIT") + ", ";
        }
        certDn = certDn.replaceAll(", $", "");   // Remove dangling ", " tail

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

    String getOptionalEnvVar(String envVar) {
        String value = System.getenv(envVar);
        if (value == null) {
            throw new RuntimeException("Mandatory environment-variable \"" + envVar + "\" is not defined");
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
            LOG.error("Exception: ", exception);
        }

        threadLocalResponseWriter.remove();
    }

    public static ThreadLocal<BufferedWriter> threadLocalResponseWriter = new ThreadLocal<>();

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
}
