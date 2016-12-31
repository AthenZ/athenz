/**
 * Copyright 2016 Yahoo Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.sia.impl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;

import org.newsclub.net.unix.AFUNIXSocket;
import org.newsclub.net.unix.AFUNIXSocketAddress;
import org.newsclub.net.unix.AFUNIXSocketException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.sia.SIA;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;

/**
 * SIA Client Library to retrieve Service Principal and the list of ZMS Domains
 * provisioned to run on this host.
 */
public class SIAClient implements SIA {

    private static final Logger LOG = LoggerFactory.getLogger(SIAClient.class);

    public static final int OP_GET_NTOKEN = 1;
    public static final int OP_LIST_DOMAINS = 2;
    
    private static int tokenMinExpiryTime = 1800;
    private static final String UNIX_SOCKET_FNAME = "/var/run/sia/sia.ds";
    private static final String ROOT_DIR = "/home/athenz";
    private static final Authority PRINCIPAL_AUTHORITY = new PrincipalAuthority();

    // Used for testing: if set, should point to the config file containing vars specifying
    // the ntoken is in a file. 
    static final String SIA_PROP_CFG_FILE = "athenz.sia.client.config_path";

    // vars used to set the config file
    static final String SIACLT_NTOKEN_PATH    = "ntoken_path";
    static final String SIACLT_NTOKEN_DOMAIN  = "ntoken_domain";
    static final String SIACLT_NTOKEN_SERVICE = "ntoken_service";

    // system property vars
    static final String SIA_PROP_NTOKEN_PATH    = "athenz.sia.client.ntoken_path";
    static final String SIA_PROP_NTOKEN_DOMAIN  = "athenz.sia.client.ntoken_domain";
    static final String SIA_PROP_NTOKEN_SERVICE = "athenz.sia.client.ntoken_service";

    static ConcurrentHashMap<String, PrincipalToken> principalTokenCache = new ConcurrentHashMap<>();

    // values obtained from the system properties and config file
    //
    static String cfgNtokenPath    = null;
    static String cfgNtokenDomain  = null;
    static String cfgNtokenService = null;

    final static String CONF_PATH = "/conf/sia_java_client/sia_client.conf";

    static {
        initConfigVars();
    }

    static void initConfigVars() {
        String ntokenPath   = null;
        String ntokenDomain = null;
        String ntokenSvc    = null;

        // load the config vars. in case of any exceptions
        // we'll just set our config variables to null and default to using
        // SIA Server for principal tokens
        
        Struct configVars = null;
        try {
            String confFile = System.getProperty(SIA_PROP_CFG_FILE);
            if (confFile == null) {
                String rootDir = System.getenv("ROOT");
                if (null == rootDir) {
                    rootDir = File.separator + "home" + File.separator + "athenz";
                }
                confFile = rootDir + CONF_PATH;
            }

            Path path = Paths.get(confFile);
            configVars = JSON.fromBytes(Files.readAllBytes(path), Struct.class);

            setupConfigVars(configVars.getString(SIACLT_NTOKEN_PATH),
                            configVars.getString(SIACLT_NTOKEN_DOMAIN),
                            configVars.getString(SIACLT_NTOKEN_SERVICE));
        } catch (Exception exc) {
            LOG.error("SIACLT: config variable initialization failure. Will use SIA Server for Principal Tokens", exc);
            cfgNtokenPath = null;
            cfgNtokenDomain = null;
            cfgNtokenService = null;
            return;
        }

        // load the System properties
        // if set, they over-ride the config variables. in case of any exceptions
        // we'll just set our config variables to null and default to using
        // SIA Server for principal tokens
        
        try {
            ntokenPath    = System.getProperty(SIA_PROP_NTOKEN_PATH);
            ntokenDomain  = System.getProperty(SIA_PROP_NTOKEN_DOMAIN);
            ntokenSvc     = System.getProperty(SIA_PROP_NTOKEN_SERVICE);
        } catch (Exception exc) {
            LOG.error("SIACLT: system property initialization failure. Will use SIA Server for Principal Tokens", exc);
            cfgNtokenPath = null;
            cfgNtokenDomain = null;
            cfgNtokenService = null;
            return;
        }

        if (ntokenPath == null || ntokenPath.isEmpty()) {
            ntokenPath = cfgNtokenPath;
        }
        if (ntokenDomain == null || ntokenDomain.isEmpty()) {
            ntokenDomain = cfgNtokenDomain;
        }
        if (ntokenSvc == null || ntokenSvc.isEmpty()) {
            ntokenSvc = cfgNtokenService;
        }
        setupConfigVars(ntokenPath, ntokenDomain, ntokenSvc);
    }

    static void setupConfigVars(String ntokenPath, String ntokenDomain, String ntokenSvc) throws IllegalArgumentException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("SIACLT:setupConfigVars: ntoken path=" + ntokenPath +
                      " domain=" + ntokenDomain + " service=" + ntokenSvc);
        }

        // make sure no empty strings(ie. "") were specified
        //
        if (ntokenPath != null && ntokenPath.isEmpty()) {
            cfgNtokenPath = null;
        } else {
            cfgNtokenPath = ntokenPath;
        }

        if (ntokenDomain != null) {
            if (ntokenDomain.isEmpty()) {
                cfgNtokenDomain = null;
            } else {
                cfgNtokenDomain = ntokenDomain.toLowerCase();
            }
        }

        if (ntokenSvc != null) {
            if (ntokenSvc.isEmpty()) {
                cfgNtokenService = null;
            } else {
                cfgNtokenService = ntokenSvc.toLowerCase();
            }
        }

        if (!((cfgNtokenPath == null && cfgNtokenDomain == null && cfgNtokenService == null) ||
            (cfgNtokenPath != null && cfgNtokenDomain != null && cfgNtokenService != null))) {
            String errMsg = "SIACLT: invalid ntoken configuration settings: " +
                "ntoken_path, ntoken_domain, ntoken_service must all be set " +
                "to use the client in a managed Athenz enabled environment";
            LOG.error(errMsg);
            throw new IllegalArgumentException(errMsg);
        }

        // build the service only if we have configured valid values
        
        if (cfgNtokenDomain != null) {
            StringBuilder sb = new StringBuilder(512);
            sb.append(cfgNtokenDomain).append(".").append(cfgNtokenService);
            cfgNtokenService = sb.toString();
        }
    }

    public SIAClient() {
    }

    String siaSocketFile() {

        String root = System.getenv("ROOT");
        if (root == null) {
            root = ROOT_DIR;
        }
        
        return root + UNIX_SOCKET_FNAME;
    }

    String getPrincipalTokenCacheKey(String domainName, String serviceName) {
        
        StringBuilder cacheKey = new StringBuilder(512);
        cacheKey.append(domainName);
        cacheKey.append(".");
        cacheKey.append(serviceName);
        return cacheKey.toString();
    }
    
    boolean isExpiredToken(long expiryTime, Integer minExpiryTime, Integer maxExpiryTime) {
        
        // we'll first make sure if we're given both min and max expiry
        // times then both conditions are satisfied
        
        if (minExpiryTime != null && expiryTime < minExpiryTime) {
            return true;
        }
        
        if (maxExpiryTime != null && expiryTime > maxExpiryTime) {
            return true;
        }

        // if both limits were null then we need to make sure
        // that our token is valid for our min configured value
        
        if (minExpiryTime == null && maxExpiryTime == null && expiryTime < tokenMinExpiryTime) {
            return true;
        }
        
        return false;
    }
    
    PrincipalToken lookupPrincipalTokenInCache(String cacheKey, Integer minExpiryTime, Integer maxExpiryTime) {

        PrincipalToken principalToken = principalTokenCache.get(cacheKey);
        if (principalToken == null) {
            return null;
        }
        
        // before returning our cache hit we need to make sure it
        // satisfies the time requirements as specified by the client
        
        long expiryTime = principalToken.getExpiryTime() - (System.currentTimeMillis() / 1000);
        
        if (isExpiredToken(expiryTime, minExpiryTime, maxExpiryTime)) {
            principalTokenCache.remove(cacheKey);
            return null;
        }
        
        return principalToken;
    }
    
    int readResponseData(InputStream is, byte[] data) throws IOException {

        int read;
        int offset = 0;
        int length = data.length;

        while (true) {
            read = is.read(data, offset, length);
            if (read == -1) {
                break;
            }

            offset += read;
            length -= read;

            if (length == 0) {
                break;
            }
        }

        return offset;
    }

    Socket getSIADomainSocket() throws IOException {
        File socketFile = new File(siaSocketFile());
        AFUNIXSocket sock = AFUNIXSocket.newInstance();
        try {
            sock.connect(new AFUNIXSocketAddress(socketFile));
        } catch (AFUNIXSocketException e) {
            throw e;
        }
        return sock;
    }
    
    String processRequest(Socket sock, int sia_op, byte[] data) throws IOException {

        String response = null;
        try (InputStream is = sock.getInputStream();
             OutputStream os = sock.getOutputStream()) {

            // first we are going to write our magic number
            
            ByteBuffer dsBytes = ByteBuffer.allocate(4);
            dsBytes.order(ByteOrder.LITTLE_ENDIAN);
            dsBytes.putInt(0x534941);
            os.write(dsBytes.array());
            
            // next we are going to write our operation code
            
            dsBytes.clear();
            dsBytes.putInt(sia_op);
            os.write(dsBytes.array());
            
            // next write the length of our data which should be 4 bytes
            
            dsBytes.clear();
            dsBytes.putInt(data != null ? data.length : 0);
            os.write(dsBytes.array());
            
            // now write our data
            
            if (data != null) {
                os.write(data);
            }
            
            os.flush();
            
            // first read the response status
            
            byte[] retCodeBytes = new byte[4];
            int read = readResponseData(is, retCodeBytes);
            if (read != 4) {
                throw new IOException("Unable to read response return code");
            }
            
            ByteBuffer retBytes = ByteBuffer.wrap(retCodeBytes);
            retBytes.order(ByteOrder.LITTLE_ENDIAN);
            int retCode = retBytes.getInt();
            
            if (retCode != 0) {
                throw new IOException("Server failed to process request - error: " + retCode);
            }
            
            // next read the response length
            
            byte[] dataSize = new byte[4];
            read = readResponseData(is, dataSize);
            if (read != 4) {
                throw new IOException("Unable to read response length");
            }
            
            ByteBuffer dataBytes = ByteBuffer.wrap(dataSize);
            dataBytes.order(ByteOrder.LITTLE_ENDIAN);
            int dataLen = dataBytes.getInt();
            
            // now read the rest of the data
            
            byte[] buf = new byte[dataLen];
            read = readResponseData(is, buf);
            if (read != dataLen) {
                throw new IOException("Read partial data: " + read + " vs. " + dataLen);
            }

            response = new String(buf, "UTF-8");
        }
        
        return response;
    }

    byte[] tokenRequestBuilder(String domainName, String serviceName, Integer maxExpiryTime) {
        
        StringBuilder reqBuilder = new StringBuilder(512);
        reqBuilder.append("d=");
        reqBuilder.append(domainName);
        reqBuilder.append(",s=");
        reqBuilder.append(serviceName);
        if (maxExpiryTime != null) {
            reqBuilder.append(",e=");
            reqBuilder.append(maxExpiryTime);
        }
        return reqBuilder.toString().getBytes(StandardCharsets.UTF_8);
    }
    
    String getSIAPrincipalToken(String domainName, String serviceName, Integer maxExpiryTime) throws IOException {
        
        byte[] req = tokenRequestBuilder(domainName, serviceName, maxExpiryTime);
        
        String token = null;
        Socket sock = null;
        try {
            sock = getSIADomainSocket();
            token = processRequest(sock, OP_GET_NTOKEN, req);
        } finally {
            if (sock != null) {
                sock.close();
            }
        }
        
        return token;
    }

    /**
     * For the specified domain/service return the corresponding Service Principal that
     * includes the SIA generated PrincipalToken (NToken)
     * @param domainName name of the domain
     * @param serviceName name of the service
     * @param minExpiryTime (optional) specifies that the returned PrincipalToken must be
     *          at least valid (min/lower bound) for specified number of seconds,
     * @param maxExpiryTime (optional) specifies that the returned PrincipalToken must be
     *          at most valid (max/upper bound) for specified number of seconds.
     * @param ignoreCache ignore the cache and retrieve the token from SIA Server
     * @return SIA generated Principal object with PrincipalToken
     * @throws IOException for IO errors
     */
    public Principal getServicePrincipal(String domainName, String serviceName,
            Integer minExpiryTime, Integer maxExpiryTime, boolean ignoreCache)
            throws IOException {

        if (domainName  == null || domainName.isEmpty() ||
            serviceName == null || serviceName.isEmpty()) {

            String errMsg = "get service principal: both domain and service names are required";
            LOG.error("SIACLT: " + errMsg);
            throw new IOException(errMsg);
        }

        // normalize our domain and service names to lower case
        
        domainName  = domainName.toLowerCase();
        serviceName = serviceName.toLowerCase();
        
        // first lookup in our cache to see if it can be satisfied
        // only if we're not asked to ignore the cache
        
        String nToken = null;
        String cacheKey = getPrincipalTokenCacheKey(domainName, serviceName);
        if (!ignoreCache) {
            PrincipalToken principalToken = lookupPrincipalTokenInCache(cacheKey, minExpiryTime, maxExpiryTime);
            if (principalToken != null) {
                nToken = principalToken.getSignedToken();
            }
        }
        
        if (nToken == null) {

            // get ntoken from file path if configured, else retrieve from SIA server
            //
            if (cfgNtokenPath != null) {
                nToken = getFilePrincipalToken(domainName, serviceName);
            } else {
        
                // retrieve a new PrincipalToken from SIA Server if we didn't
                // satisfy the request from our cache
                //
                nToken = getSIAPrincipalToken(domainName, serviceName, maxExpiryTime);
        
                // create and put a new PrincipalToken object in the cache and
                // return a newly created principal object
        
                PrincipalToken principalToken = new PrincipalToken(nToken);
                principalTokenCache.put(cacheKey, principalToken);
            }
        }
        
        return SimplePrincipal.create(domainName, serviceName, nToken, PRINCIPAL_AUTHORITY);
    }

    String getFilePrincipalToken(String domainName, String serviceName) throws IOException {
        StringBuilder sb = new StringBuilder(512);
        sb.append(domainName).append("."). append(serviceName);
        String svc = sb.toString().toLowerCase();
        if (!svc.equals(cfgNtokenService)) {
            String errMsg = "SIACLT: get ntoken from file: Unknown service=" +
                svc + " Configured service=" + cfgNtokenService;
            LOG.error(errMsg);
            throw new IOException(errMsg);
        }

        Path path = Paths.get(cfgNtokenPath);
        String token = new String(Files.readAllBytes(path));
        if (token != null && !token.isEmpty()) {
            token = token.trim();
            int index = token.indexOf('\n');
            if (index != -1) {
                token = token.substring(0, index);
            }
        }
        return token;
    }

    /**
     * Returns the list of domains that have private keys registered on this host
     * @return List of domain names
     * @throws IOException for any IO errors
     */
    public ArrayList<String> getDomainList() throws IOException {

        String domains = null;
        Socket sock = null;
        try {
            sock = getSIADomainSocket();
            domains = processRequest(sock, OP_LIST_DOMAINS, null);
        } finally {
            if (sock != null) {
                sock.close();
            }
        }
        
        StringTokenizer st = new StringTokenizer(domains, ";");
        ArrayList<String> domainList = new ArrayList<String>();
        while (st.hasMoreTokens()) {
            domainList.add(st.nextToken());
        }

        return domainList;
    }
}
