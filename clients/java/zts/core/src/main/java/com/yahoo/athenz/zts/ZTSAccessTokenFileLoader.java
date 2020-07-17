package com.yahoo.athenz.zts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class ZTSAccessTokenFileLoader {

    private static final Logger LOG = LoggerFactory.getLogger(ZTSAccessTokenFileLoader.class);

    static public final String ACCESS_TOKEN_PATH_PROPERTY = "athenz.zts.client.accesstoken.path";
    static private final String DEFAULT_ACCESS_TOKEN_DIR_PATH = "/var/lib/sia/tokens/";
    static private final String ROLE_NAME_CONNECTOR = ",";
    static private final String DOMAIN_ROLE_CONNECTOR = ":role:";
    final private String path;
    private JwtsSigningKeyResolver accessSignKeyResolver;
    private ObjectMapper objectMapper = new ObjectMapper();
    private Map<String, String> roleNameMap;

    public ZTSAccessTokenFileLoader(JwtsSigningKeyResolver resolver) {
        roleNameMap = new HashMap<>();
        accessSignKeyResolver = resolver;
        path = System.getProperty(ACCESS_TOKEN_PATH_PROPERTY, DEFAULT_ACCESS_TOKEN_DIR_PATH);
    }

    public void preload() {
        File dir = new File(path);

        // preload the map from the <domain, rolesname> -> <file path>
        // expected dir should be <base token path>/<domain dir>/<token file>s
        // after preload the map, when we look up the access token,
        // the map will directly read the required file
        if (dir.exists() && dir.isDirectory()) {
            for (File domainDir: dir.listFiles()) {
                if (domainDir.isDirectory()) {
                    for (File tokenFile: domainDir.listFiles()) {
                        if (!tokenFile.isDirectory()) {
                            AccessTokenResponse accessTokenResponse = null;
                            try {
                                accessTokenResponse = objectMapper.readValue(tokenFile, AccessTokenResponse.class);
                            } catch (IOException e) {
                                LOG.error("Failed to load or parse token file: {}", tokenFile);
                            }

                            // if access token parsed fail, continue to scan tokens
                            if (accessTokenResponse == null) {
                                continue;
                            }

                            AccessTokenResponseCacheEntry cacheEntry = new AccessTokenResponseCacheEntry(accessTokenResponse);

                            // check access token is still valid
                            if (!cacheEntry.isExpired(-1)) {
                                addToRoleMap(domainDir.getName(), tokenFile.getName(), accessTokenResponse);
                            }
                        }
                    }
                }
            }
        }

    }

    // function load the access token from file
    public AccessTokenResponse lookupAccessTokenFromDisk(String domain, List<String> rolesName) throws IOException {
        final String rolesStr = getRolesStr(domain, rolesName);
        final String fileName = roleNameMap.get(rolesStr);
        LOG.debug("Trying to fetch access token from disk for domain: {}, roleNames: {}, roleMap key: {}. file name: {}",
                domain, rolesName, rolesStr, fileName);
        if (fileName == null) {
            return null;
        }
        File tokenFile = new File(path + File.separator + domain + File.separator + fileName);

        return objectMapper.readValue(tokenFile, AccessTokenResponse.class);
    }

    static private String getRolesStr(String domain, List<String> roleNames) {
        // in case the rolesName is immutable, make a copy of role name list
        if (roleNames == null || roleNames.isEmpty()) {
            //if no role name specific, should return all roles
            return domain + DOMAIN_ROLE_CONNECTOR + "*";
        }
        List<String> roleNamesCopy = new ArrayList<>(roleNames);
        Collections.sort(roleNamesCopy);
        return domain + DOMAIN_ROLE_CONNECTOR + String.join(ROLE_NAME_CONNECTOR, roleNamesCopy);
    }

    private void addToRoleMap(String domain, String fileName, AccessTokenResponse accessTokenResponse) {
        // parse roles from access token
        final String token = accessTokenResponse.getAccess_token();

        try {
            AccessToken accessToken = new AccessToken(token, accessSignKeyResolver);
            List<String> roleNames = accessToken.getScope();
            roleNameMap.put(getRolesStr(domain, roleNames), fileName);
        } catch (Exception e) {
            LOG.error("Got error to parse access token file {}, error: {}", fileName, e.getMessage());
            return;
        }
    }
}
