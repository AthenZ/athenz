package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.impl.PrincipalAuthority;

public class TestUserPrincipalAuthority extends PrincipalAuthority {

    public TestUserPrincipalAuthority() {
    }

    @Override
    public String getUserDomainName(String userName) {
        return userName.replace('.', '-');
    }
}
