
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.creds.gcp.GCPFunctionIdentity;
import com.yahoo.athenz.creds.gcp.GCPSIACredentials;
import com.yahoo.athenz.zts.ZTSClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.invoke.MethodHandles;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class GcfSiaTest implements HttpFunction {
    // Simple function to return "Hello World"
    @Override
    public void service(HttpRequest request, HttpResponse response)
            throws IOException {
        String allOutput = captureOutput(() -> LOG.debug("SIA CERTIFICATE:\n" + getSiaCertsDemo()));
        response.getWriter().write(allOutput);
    }

    String getSiaCertsDemo() {
        final String athenzDomain = getMandatoryEnvVar("ATHENZ_DOMAIN");
        final String athenzService = getMandatoryEnvVar("ATHENZ_SERVICE");
        final String gcpProjectId = getMandatoryEnvVar("GCP_PROJECT_ID");
        final String gcpRegion = getMandatoryEnvVar("GCP_REGION");
        final String athenzProvider = "sys.gcp." + gcpRegion;
        final String ztsUrl = getMandatoryEnvVar("ZTS_URL");
        final String certDn = "ou=Athenz,o=Oath"; // the dn you want included in cert - should not change
        final String certDomain = "gcp.yahoo.cloud"; // do not change

        X509Certificate certificate;
        PrivateKey privateKey;

        // generate a private key and retrieve the corresponding
        // certificate from Athenz ZTS Service

        try (ZTSClient client = new ZTSClient(ztsUrl)) {
            ZTSClient.setX509CsrDetails(certDn, certDomain);
            GCPFunctionIdentity gcpIdentity = GCPSIACredentials.getGCPFunctionServiceCertificate(
                    client,
                    athenzDomain,
                    athenzService,
                    gcpProjectId,
                    athenzProvider);

            certificate = gcpIdentity.getX509Certificate();
            privateKey = gcpIdentity.getPrivateKey();
        }

        // typically you'll use the privateKey and certificate objects
        // as is in your code. If you need to access those in PEM
        // format then you can use the helper functions from Crypto library

        final String pemCertificate = Crypto.convertToPEMFormat(certificate);
        final String pemPrivateKey = Crypto.convertToPEMFormat(privateKey);

        // as a test output just return our certificate in pem format so
        // we can see it in our aws console (we'll protect our private key
        // and not display it in our aws console)

        return pemCertificate;
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

    // Execute some workload, while capturing all logs (stdout+stderr).
    // If the workload throws - capture the exception and log it.
    // Return all captures logs.
    private static String captureOutput(Runnable work) {

        PrintStream origSystemOut = System.out;
        PrintStream origSystemErr = System.err;
        ByteArrayOutputStream systemOutBytes = new ByteArrayOutputStream();
        PrintStream systemOut = new PrintStream(systemOutBytes);
        System.setOut(systemOut);
        System.setErr(systemOut);

        String allOutput;
        try {
            work.run();
        } catch (Exception ex) {
            LOG.error("Exception: ", ex);
        } finally {
            System.setOut(origSystemOut);
            System.setErr(origSystemErr);
            allOutput = systemOutBytes.toString();
            System.out.println(allOutput);
        }
        return allOutput;
    }

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
}
