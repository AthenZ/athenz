package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.impl.PrincipalAuthority;

class TestUserPrincipalAuthority extends PrincipalAuthority {

    public TestUserPrincipalAuthority() {
    }

    @Override
    public String getUserDomainName(String userName) {
        return userName.replace('.', '-');
    }

    @Override
    public boolean isValidUser(String user) {
        return user.equals("user.joe") || user.equals("user.jane");
    }
}
