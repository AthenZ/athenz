
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.yahoo.athenz.creds.gcp.GCPSIACredentials;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.lang.invoke.MethodHandles;

public class GcfSiaTest implements HttpFunction {

    void getSiaCertsDemo() throws Exception {
        LOG.debug("This is JAVA GCF test");

        // Read configurations.
        final String athenzDomain = getMandatoryEnvVar("ATHENZ_DOMAIN");
        final String athenzService = getMandatoryEnvVar("ATHENZ_SERVICE");
        final String gcpProjectId = getMandatoryEnvVar("GCP_PROJECT_ID");
        final String gcpRegion = getMandatoryEnvVar("GCP_REGION");
        final String athenzProvider = "sys.gcp." + gcpRegion;
        final String ztsUrl = getMandatoryEnvVar("ZTS_URL");
        final String certDomain = getMandatoryEnvVar("CERT_DOMAIN");
        final String optionalCountry = getOptionalEnvVar("CSR_COUNTRY");
        final String optionalState = getOptionalEnvVar("CSR_STATE");
        final String optionalLocality = getOptionalEnvVar("CSR_LOCALITY");
        final String optionalOrganization = getOptionalEnvVar("CSR_ORGANIZATION");
        final String optionalOrganizationUnit = getOptionalEnvVar("CSR_ORGANIZATION_UNIT");

        // Generate a private key and retrieve the corresponding certificate from Athenz ZTS Service.
        GCPSIACredentials.PrivateAndCertificate privateAndCertificate = GCPSIACredentials.getGCPFunctionServiceCertificate(
                athenzDomain,
                athenzService,
                gcpProjectId,
                athenzProvider,
                ztsUrl,
                certDomain,
                optionalCountry,
                optionalState,
                optionalLocality,
                optionalOrganization,
                optionalOrganizationUnit);

        LOG.debug("SIA CERTIFICATE:\n" + convertToPEMFormat(privateAndCertificate.certificate));
        // LOG.debug("SIA PRIVATE-KEY:\n" + convertToPEMFormat(privateAndCertificate.privateKey));     Commented out: too sensitive
    }

    public static String convertToPEMFormat(Object obj) {
        StringWriter writer = new StringWriter();
        try {
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(obj);
                pemWriter.flush();
            }
        } catch (IOException exception) {
            LOG.error("convertToPEMFormat: unable to convert object to PEM: ", exception);
            return null;
        }
        return writer.toString();
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
