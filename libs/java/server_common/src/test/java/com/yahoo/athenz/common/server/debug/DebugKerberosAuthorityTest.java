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
package com.yahoo.athenz.common.server.debug;

import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

import static org.testng.Assert.*;

public class DebugKerberosAuthorityTest {

    private static final String KRB_TOKEN = "YIIB6wYJKoZIhvcSAQICAQBuggHaMIIB1qADAgEFoQMCAQ6iBwMFAAAAAACjggEGYYIBAjCB/6ADAgEFoQ0bC0VYQU1QTEUuQ09NojAwLqADAgEAoScwJRsHZGF0YWh1YhsTZGF0YWh1Yi5leGFtcGxlLmNvbRsFYnVsbHmjgbYwgbOgAwIBA6KBqwSBqMJGf4H5nrRIdDyNxHp5fwxW6lsiFi+qUjryPvgiOAl/XldfwmKd9wXbQn00VBNhK+oVxmKv0V0J80e4oTdUnc+NlU/BJNCfsLPFTdYntc4A/ffdnsY7/U5HktTaWMfhvWxYocvhqISFTIFUT1+pH5742IWYNTgvFd5vkudibB3ijCanbMYv9CQXEjV+380rnf3gdLD2JGuxmaU78aJjDDKETL6Ck/qz8KSBtjCBs6ADAgEDooGrBIGoMrzLCTUi59wEoWX02+42K5m1MzW6HMNSuvfQeVGJdzPBsiFmZweNfJF6L9LdmLjQR4jSVUhVo3neFZmUN8G532wvZeKbHOtkXTnLRRdif+DoKyI8GOkbHu1CZlevcQZ0sgzyiH0wfQ/0nguE4kH7a2bM7HlV7N6MRGkC4DDkJZDNHxQr27FbZqrqEyw498HXPTtF93JGsKjXB8Z/wDaPs4PpdfoThTol";
    private static final String ATHENZ_USER_DOMAIN = "athenz.user_domain";
    private static final String USER_DOMAIN = System.getProperty(ATHENZ_USER_DOMAIN, "user");
    
    @Test
    public void testDebugKerberosAuthority() {

        Authority authority = new DebugKerberosAuthority();
        assertNotNull(authority);

        authority.initialize();

        assertEquals(authority.getDomain(), USER_DOMAIN);
        assertEquals(authority.getHeader(), DebugKerberosAuthority.KRB_HEADER);
 
        // invalid authenticate values
        assertNull(authority.authenticate(null, "6.21.20.16", "GET", null));
        assertNull(authority.authenticate("abc", "6.21.20.16", "GET", null));
        assertNull(authority.authenticate(KRB_TOKEN, "6.21.20.16", "GET", null));

        // valid values
        Principal prnc = authority.authenticate(DebugKerberosAuthority.TOKEN_PREFIX + " " + KRB_TOKEN, "6.21.20.16", "GET", null);
        assertNotNull(prnc);
        assertEquals(prnc.getDomain(), USER_DOMAIN);
        assertEquals(prnc.getName(), "anonymous");
        assertEquals(prnc.getCredentials(), KRB_TOKEN);
        assertNull(prnc.getRoles());
    }

    @Test
    public void testDebugKerberosAuthoritySysProp() {

        System.setProperty(DebugKerberosAuthority.ATHENZ_PROP_USER_NAME, "tiesto");

        Authority authority = new DebugKerberosAuthority();
        assertNotNull(authority);

        authority.initialize();

        assertEquals(authority.getDomain(), USER_DOMAIN);
        assertEquals(authority.getHeader(), DebugKerberosAuthority.KRB_HEADER);
 
        // invalid authenticate values
        assertNull(authority.authenticate(null, "6.21.20.16", "GET", null));
        assertNull(authority.authenticate("abc", "6.21.20.16", "GET", null));
        assertNull(authority.authenticate(KRB_TOKEN, "6.21.20.16", "GET", null));

        // valid values
        Principal prnc = authority.authenticate(DebugKerberosAuthority.TOKEN_PREFIX + " " + KRB_TOKEN, "6.21.20.16", "GET", null);
        assertNotNull(prnc);
        assertEquals(prnc.getDomain(), USER_DOMAIN);
        assertEquals(prnc.getName(), "tiesto");
        assertEquals(prnc.getCredentials(), KRB_TOKEN);
        assertNull(prnc.getRoles());

        // now use debug token that contains user name
        String token = DebugKerberosAuthority.TOKEN_PREFIX + " " + DebugKerberosAuthority.TOKEN_DEBUG_USER_FIELD + "jamesdean";
        prnc = authority.authenticate(token, "6.21.20.16", "GET", null);
        assertNotNull(prnc);
        assertEquals(prnc.getDomain(), USER_DOMAIN);
        assertEquals(prnc.getName(), "jamesdean");
        assertEquals(prnc.getCredentials(), DebugKerberosAuthority.TOKEN_DEBUG_USER_FIELD + "jamesdean");
        assertNull(prnc.getRoles());

        System.clearProperty(DebugKerberosAuthority.ATHENZ_PROP_USER_NAME);
    }
}

