/*
 * Copyright The Athenz Authors
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
package com.yahoo.athenz.auth.impl;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.callback.CallbackHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.KerberosToken;

/**
 * An Authority can validate credentials of a Principal in its domain. It also can provide HTTP header information
 * that determines where to find relevant credentials for that task.
 */
public class KerberosAuthority implements Authority {

    private static final Logger LOG = LoggerFactory.getLogger(KerberosAuthority.class);

    static final String KRB_AUTH_HEADER    = "Authorization";
    static final String KRB_AUTH_CHALLENGE = "Negotiate";
    static final String KRB_PROP_SVCPRPL   = "athenz.auth.kerberos.service_principal";
    static final String KRB_PROP_KEYTAB    = "athenz.auth.kerberos.keytab_location";
    static final String KRB_PROP_DEBUG     = "athenz.auth.kerberos.debug";
    
    // This is used if there is a jaas.conf. The jaas.conf path is specified by the system property 
    // java.security.auth.login.config
    static final String KRB_PROP_JAASCFG              = "athenz.auth.kerberos.jaas_cfg_section";
    static final String KRB_PROP_LOGIN_CB_CLASS       = "athenz.auth.kerberos.login_callback_handler_class";
    static final String KRB_PROP_LOGIN_RENEW_TGT      = "athenz.auth.kerberos.renewTGT"; // "true" or "false"
    static final String KRB_PROP_LOGIN_USE_TKT_CACHE  = "athenz.auth.kerberos.use_ticket_cache"; // "true" or "false"
    static final String KRB_PROP_LOGIN_TKT_CACHE_NAME = "athenz.auth.kerberos.ticket_cache_name"; // file path
    static final String KRB_PROP_LOGIN_WINDOW         = "athenz.auth.kerberos.login_window"; // millis used to determine re-login

    static final String LOGIN_WINDOW_DEF = "60000"; // 60 seconds default

    private String  servicePrincipal; // ex: HTTP/localhost@LOCALHOST
    private String  keyTabConfFile;
    private String  jaasConfigSection;
    private final String  loginCallbackHandler;
    private final AtomicReference<Subject> serviceSubject = new AtomicReference<>();
    private Exception initState = null;

    private long lastLogin   = 0; // last time logged in in millisecs
    private long loginWindow = 60000;

    public KerberosAuthority(String servicePrincipal, String keyTabConfFile, String jaasConfigSection) {

        this();
        if (servicePrincipal != null && !servicePrincipal.isEmpty()) {
            this.servicePrincipal  = servicePrincipal;
        }
        if (keyTabConfFile != null && !keyTabConfFile.isEmpty()) {
            this.keyTabConfFile = keyTabConfFile;
        }
        this.jaasConfigSection = Objects.requireNonNullElse(jaasConfigSection, "");
    }

    public KerberosAuthority() {
        servicePrincipal     = getConfigValue(KRB_PROP_SVCPRPL);
        keyTabConfFile       = getConfigValue(KRB_PROP_KEYTAB);
        jaasConfigSection    = System.getProperty(KRB_PROP_JAASCFG, "");
        loginCallbackHandler = getConfigValue(KRB_PROP_LOGIN_CB_CLASS);
        loginWindow          = Long.decode(System.getProperty(KRB_PROP_LOGIN_WINDOW, LOGIN_WINDOW_DEF));
    }

    String getConfigValue(final String property) {
        final String value = System.getProperty(property);
        return (value != null && !value.isEmpty()) ? value : null;
    }

    public Exception getInitState() {
        return initState;
    }
    public void setInitState(Exception exc) {
        initState = exc;
    }

    public long getLoginWindow() {
        return loginWindow;
    }
    public void setLoginWindow(long loginWindowMillis) {
        loginWindow = loginWindowMillis;
    }

    public long getLastLogin() {
        return lastLogin;
    }

    /**
     * Initialize the authority
     */
    @Override
    public void initialize() {
        login(false);
    }

    @Override
    public String getID() {
        return "Auth-KERB";
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public synchronized void login(boolean logoutFirst) {

        long now = System.currentTimeMillis();
        if ((now - lastLogin) < loginWindow) {
            // recently logged in so dont bother do it again
            return;
        }

        Subject subject = null;
        if (servicePrincipal != null) {
            Set<java.security.Principal> principals = new HashSet<>(1);
            principals.add(new KerberosPrincipal(servicePrincipal));

            subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());
        }

        LoginConfig loginConfig = new LoginConfig(keyTabConfFile, servicePrincipal);
        initState = null;
        try {
            // NOTE: if no callback handler specified
            // LoginContext uses the auth.login.defaultCallbackHandler security property for the fully 
            // qualified class name of a default handler implementation
            LoginContext    loginContext;
            CallbackHandler loginHandler = null;
            if (loginCallbackHandler != null && !loginCallbackHandler.isEmpty()) {
                Class cbhandlerClass = Class.forName(loginCallbackHandler);
                loginHandler = (CallbackHandler) cbhandlerClass.getConstructor(String.class, String.class).newInstance(servicePrincipal, null);
            }
            
            if (subject == null) {
                loginContext = new LoginContext(jaasConfigSection, Objects.requireNonNull(loginHandler));
            } else {
                loginContext = new LoginContext(jaasConfigSection, subject, loginHandler, loginConfig);
            }
            
            if (logoutFirst) {
                loginContext.logout();
            }
            loginContext.login();
            subject = loginContext.getSubject();
            serviceSubject.set(subject);
            lastLogin = System.currentTimeMillis();
            
        } catch (Exception exc) {
            initState = exc;
            String params = "svc-princ=" + servicePrincipal + " login-callback=" + loginCallbackHandler +
                " keytab=" + keyTabConfFile + " jaas-section=" + jaasConfigSection;
            LOG.error("KerberosAuthority:initialize: Login context failure: config params=({}) exc: {}", params, exc.getMessage());
        }
    }

    boolean isTargetPrincipal(KerberosTicket ticket, String remoteSvcPrincipal) {
        if (ticket == null) {
            return false;
        }

        KerberosPrincipal principal = ticket.getServer();
        if (LOG.isDebugEnabled()) {
            LOG.debug("KerberosAuthority:isTargetPrincipal: our princ={} ticket princ={}",
                    servicePrincipal, principal.getName());
        }

        return principal.getName().equals(remoteSvcPrincipal);
    }

    /**
     * Determines if refresh login needed if the ticket for the specified
     * remoteSvcPrincipal has expired or is not found.
     * @param remoteSvcPrincipal remote service principal
     * @return true if refresh is required, false otherwise (ticket is still valid)
     */
    public boolean refreshLogin(String remoteSvcPrincipal) {
        // check for expiration
        // get the original ticket from the serviceSubject
        Subject subject = serviceSubject.get();
        KerberosTicket tgt = null;
        Set<KerberosTicket> tickets = subject.getPrivateCredentials(KerberosTicket.class);
        for (KerberosTicket ticket : tickets) {
            if (isTargetPrincipal(ticket, remoteSvcPrincipal)) {
                tgt = ticket;
                break;
            }
        }

        if (tgt == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("KerberosAuthority:refreshLogin: Process tickets found no principal match: subject contains number of tickets={}",
                        tickets.size());
            }
            return true;
        }
        long end = tgt.getEndTime().getTime();
        long now = System.currentTimeMillis();
        if (now > end) {
            login(true);
            return true;
        }
        return false;
    }

    /**
     * @return the domain of the authority, defaults to "ygrid"
     */
    @Override
    public String getDomain() {
        return null;
    }

    @Override
    public String getHeader() {
        return KRB_AUTH_HEADER;
    }

    @Override
     public String getAuthenticateChallenge() {
        return KRB_AUTH_CHALLENGE;
    }

    /**
     * Verify the credentials and if valid return the corresponding Principal, null otherwise.
     * @param creds the credentials (i.e. cookie, token, secret) that will identify the principal.
     * @param remoteAddr remote IP address of the connection
     * @param httpMethod the http method for this request (e.g. GET, PUT, etc)
     * @param errMsg will contain error message if authenticate fails
     * @return the Principal for the credentials, or null if the credentials are not valid.
     */
    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {

        KerberosToken token;
        try {
            token = new KerberosToken(creds, remoteAddr);
        } catch (IllegalArgumentException ex) {
            if (errMsg == null) {
                errMsg = new StringBuilder();
            }
            errMsg.append("KerberosAuthority:authenticate: Invalid token: exc=").
                   append(ex.getMessage()).append(" : credential=").
                   append(creds);
            LOG.error("KerberosAuthority:authenticate: {}", errMsg);
            return null;
        }

        StringBuilder errDetail = new StringBuilder(512);
        if (!token.validate(serviceSubject.get(), errDetail)) {
            if (errMsg != null) {
                errMsg.append("KerberosAuthority:authenticate: token validation failure: ");
                errMsg.append(errDetail);
            }
            return null;
        }

        String userDomain = token.getDomain();
        String userName   = token.getUserName();
        if (userName == null) {
            if (errMsg != null) {
                errMsg.append("KerberosAuthority:authenticate: token validation failure: missing user");
            }
            return null;
        }
        return SimplePrincipal.create(userDomain, userName, creds, this);
    }

    static class LoginConfig extends Configuration {
        private final String keyTabConfFile;
        private final String servicePrincipalName;
        private final boolean debugKrbEnabled;

        public LoginConfig(String keyTabConfFile, String servicePrincipalName) {
            this.keyTabConfFile       = keyTabConfFile;
            this.servicePrincipalName = servicePrincipalName;
            debugKrbEnabled = Boolean.parseBoolean(System.getProperty(KRB_PROP_DEBUG, "false"));
        }

        public boolean isDebugEnabled() {
            return debugKrbEnabled;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<>();
            if (keyTabConfFile == null || keyTabConfFile.isEmpty()) {
                options.put("useKeyTab", "false");
                options.put("tryFirstPass", "true");
            } else {
                options.put("useKeyTab", "true");
                options.put("keyTab", keyTabConfFile);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("KerberosAuthority:authenticate: use keytab={}", keyTabConfFile);
                }
            }
            options.put("principal", servicePrincipalName);
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            String useTktCache = System.getProperty(KRB_PROP_LOGIN_USE_TKT_CACHE, "true");
            options.put("useTicketCache", useTktCache);
            String renewTgt = System.getProperty(KRB_PROP_LOGIN_RENEW_TGT, "true");
            options.put("renewTGT", renewTgt);
            /*
             * refreshKrb5Config is very important. Without that not able to login
             * more than one principal. Fails with
             * "KeyTab instance already exists. Unable to obtain password from user"
             */
            options.put("refreshKrb5Config", "true");
            
            // If "ticketCache" is set, "useTicketCache" must also be set to true;
            // Otherwise a configuration error will be returned
            if (Boolean.parseBoolean(useTktCache)) {
                String ticketCacheName = System.getenv("KRB5CCNAME");  // this is what hadoop does
                if (ticketCacheName != null) {
                    options.put("ticketCache", ticketCacheName);
                } else {
                    ticketCacheName = System.getProperty(KRB_PROP_LOGIN_TKT_CACHE_NAME);
                    if (ticketCacheName != null && !ticketCacheName.isEmpty()) {
                        options.put("ticketCache", ticketCacheName);
                    }
                }
            }
            
            if (debugKrbEnabled) {
                options.put("debug", "true");
            }
            options.put("isInitiator", "false");

            return new AppConfigurationEntry[] {
                new AppConfigurationEntry(
                    "com.sun.security.auth.module.Krb5LoginModule",
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)
            };
        }
    }
}

