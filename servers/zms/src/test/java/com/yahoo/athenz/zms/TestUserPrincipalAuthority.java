package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;

class TestUserPrincipalAuthority extends PrincipalAuthority {

    public TestUserPrincipalAuthority() {
    }

    @Override
    public String getUserDomainName(String userName) {
        return userName.replace('.', '-');
    }

    @Override
    public Authority.UserType getUserType(String user) {
        switch (user) {
            case "user.joe":
            case "user.jane":
            case "user.jack":
                return UserType.USER_ACTIVE;
            default:
                return UserType.USER_INVALID;
        }
    }

    @Override
    public boolean isAttributeSet(String user, String attributeName) {

        // joe and jane are employees while jack is a contractor
        // all users are local users

        if ("employee".equals(attributeName)) {
            return user.equals("user.joe") || user.equals("user.jane");
        } else if ("contractor".equals(attributeName)) {
            return user.equals("user.jack");
        } else if ("local".equals(attributeName)) {
            return user.equals("user.joe") || user.equals("user.jane") || user.equals("user.jack");
        } else {
            return false;
        }
    }

    @Override
    public String getUserManager(String userName) {
        if (userName.equals("user.joe")) {
            return "user.jane";
        } else if (userName.equals("user.jane")) {
            return "user.jack";
        } else {
            return null;
        }
    }
}
