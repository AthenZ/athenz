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
package com.yahoo.athenz.auth.token;

import java.security.PrivilegedExceptionAction;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedActionException;
import javax.security.auth.Subject;

import org.bouncycastle.util.encoders.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KerberosToken extends Token {

    private static final Logger LOG = LoggerFactory.getLogger(KerberosToken.class);

    public static final String KRB_AUTH_VAL_FLD = "Negotiate";
    public static final String KRB_PROP_TOKEN_PRIV_ACTION = "athenz.auth.kerberos.krb_privileged_action_class";
    private static final String ATHENZ_PROP_USER_DOMAIN = "athenz.user_domain";
    private static final String ATHENZ_PROP_USER_REALM = "athenz.auth.kerberos.user_realm";
    private static final String ATHENZ_PROP_KRB_USER_DOMAIN = "athenz.auth.kerberos.krb_user_domain";
    private static final String ATHENZ_PROP_KRB_USER_REALM = "athenz.auth.kerberos.krb_user_realm";

    private final String krbPrivActionClass = System.getProperty(KRB_PROP_TOKEN_PRIV_ACTION);
    private String userName = null;
    
    public static final String USER_DOMAIN = System.getProperty(ATHENZ_PROP_USER_DOMAIN, "user");
    private static final String USER_REALM = System.getProperty(ATHENZ_PROP_USER_REALM, "USER_REALM");
    public static final String KRB_USER_DOMAIN = System.getProperty(ATHENZ_PROP_KRB_USER_DOMAIN, "krb");
    public static final String KRB_USER_REALM = System.getProperty(ATHENZ_PROP_KRB_USER_REALM, "KRB_REALM");
    
    public KerberosToken(String creds, String remoteAddr) {
        if (creds == null || creds.isEmpty()) {
            LOG.error("KerberosToken: Missing credentials");
            throw new IllegalArgumentException("KerberosToken: creds must not be empty");
        }

        if (!creds.startsWith(KRB_AUTH_VAL_FLD)) {
            throw new IllegalArgumentException("KerberosToken: creds do not contain required Negotiate component");
        }

        signedToken   = creds;
        unsignedToken = creds.substring(KRB_AUTH_VAL_FLD.length()).trim();
        domain        = KRB_USER_DOMAIN;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public boolean validate(Subject serviceSubject, StringBuilder errMsg) {
    
        PrivilegedExceptionAction<String> privExcAction;
        try {
            byte[] kerberosTicket = Base64.decode(unsignedToken.getBytes(StandardCharsets.UTF_8));
            if (krbPrivActionClass != null && !krbPrivActionClass.isEmpty()) {
                Class privActionClass = Class.forName(krbPrivActionClass);
                privExcAction = (PrivilegedExceptionAction<String>) privActionClass.getConstructor(byte[].class).newInstance((Object) kerberosTicket);
            } else {
                privExcAction = new KerberosValidateAction(kerberosTicket);
            }
            userName = Subject.doAs(serviceSubject, privExcAction);
            int index = userName.indexOf('@');
            if (index != -1) {
                if (userName.indexOf(KRB_USER_REALM, index) == -1) {
                    if (userName.indexOf(USER_REALM, index) != -1) {
                        domain = USER_DOMAIN;
                    } else {
                        throw new Exception("KerberosToken:validate: invalid Kerberos Realm: " + userName);
                    }
                }
                userName = userName.substring(0, index);
            }
            return true;

        } catch (PrivilegedActionException paexc) {
            if (errMsg == null) {
                errMsg = new StringBuilder(512);
            }
            errMsg.append("KerberosToken:validate: token=").append(unsignedToken).
                   append(" : privilege exc=").append(paexc);
            LOG.error(errMsg.toString());
        } catch (Exception exc) {
            if (errMsg == null) {
                errMsg = new StringBuilder(512);
            }
            errMsg.append("KerberosToken:validate: token=").append(unsignedToken).
                   append(" : unknown exc=").append(exc);
            LOG.error(errMsg.toString());
        }
        return false;
    }

    public String getUserName() {
        return userName;
    }

    private static class KerberosValidateAction implements PrivilegedExceptionAction<String> {
        final byte[] kerberosTicket;

        KerberosValidateAction(byte[] kerberosTicket) {
            this.kerberosTicket = kerberosTicket;
        }

        @Override
        public String run() throws Exception {
            GSSContext context = GSSManager.getInstance().createContext((GSSCredential) null);
            context.acceptSecContext(kerberosTicket, 0, kerberosTicket.length);
            String user = context.getSrcName().toString();
            context.dispose();
            return user;
        }
    }
}
