package com.yahoo.athenz.auth.util;

import com.yahoo.athenz.auth.ServerPrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.security.PrivateKey;
import java.util.function.Function;

public class PrivateKeyStoreUtil {
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String ZMS_SERVICE = "zms";
    private static final String ZTS_SERVICE = "zts";
    private static final String MSD_SERVICE = "msd";

    private static final String ATHENZ_PROP_ZMS_KEY_NAME    = "athenz.aws.zms.key_name";
    private static final String ATHENZ_PROP_ZMS_KEY_ID_NAME = "athenz.aws.zms.key_id_name";
    private static final String ATHENZ_PROP_ZTS_KEY_NAME    = "athenz.aws.zts.key_name";
    private static final String ATHENZ_PROP_ZTS_KEY_ID_NAME = "athenz.aws.zts.key_id_name";
    private static final String ATHENZ_PROP_MSD_KEY_NAME    = "athenz.aws.msd.key_name";
    private static final String ATHENZ_PROP_MSD_KEY_ID_NAME = "athenz.aws.msd.key_id_name";

    private static final String ATHENZ_DEFAULT_KEY_NAME     = "service_private_key";
    private static final String ATHENZ_DEFAULT_KEY_ID_NAME  = "service_private_key_id";

    public static ServerPrivateKey getPrivateKeyFromCloudParameter(String service, String region, String algorithm, Function<String, String> getParameterFn) {
        if (region == null || region.isEmpty()) {
            LOG.error("server region not specified");
            return null;
        }
        String keyName;
        String keyIdName;
        final String objectSuffix = "." + algorithm.toLowerCase();
        if (ZMS_SERVICE.equals(service)) {
            keyName = System.getProperty(ATHENZ_PROP_ZMS_KEY_NAME, ATHENZ_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_ZMS_KEY_ID_NAME, ATHENZ_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else if (ZTS_SERVICE.equals(service)) {
            keyName = System.getProperty(ATHENZ_PROP_ZTS_KEY_NAME, ATHENZ_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_ZTS_KEY_ID_NAME, ATHENZ_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else if (MSD_SERVICE.equals(service)) {
            keyName = System.getProperty(ATHENZ_PROP_MSD_KEY_NAME, ATHENZ_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_MSD_KEY_ID_NAME, ATHENZ_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else {
            LOG.error("Unknown service specified: {}", service);
            return null;
        }

        PrivateKey pkey = null;
        try {
            pkey = Crypto.loadPrivateKey(getParameterFn.apply(keyName));
        } catch (Exception ex) {
            LOG.error("unable to load private key: {}, error: {}", keyName, ex.getMessage());
        }

        return pkey == null
                ? null
                : new ServerPrivateKey(pkey, getParameterFn.apply(keyIdName));
    }
}
