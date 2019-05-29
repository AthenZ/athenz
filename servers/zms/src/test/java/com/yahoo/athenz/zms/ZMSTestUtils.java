/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.zms;

import com.yahoo.rdl.Timestamp;

import java.util.List;

public class ZMSTestUtils {

    public static boolean verifyDomainRoleMember(List<DomainRoleMember> members, String memberName,
            String... roles) {

        for (DomainRoleMember member : members) {
            if (member.getMemberName().equals(memberName)) {
                List<MemberRole> memberRoles = member.getMemberRoles();
                if (memberRoles.size() != roles.length) {
                    return false;
                }
                for (String role : roles) {
                    Boolean bMatchFound = false;
                    for (MemberRole memberRole : memberRoles) {
                        if (memberRole.getRoleName().equals(role)) {
                            bMatchFound = true;
                            break;
                        }
                    }
                    if (!bMatchFound) {
                        return false;
                    }
                }

                return true;
            }
        }

        return false;
    }

    public static boolean verifyDomainRoleMemberExpiry(List<DomainRoleMember> members, String memberName,
            String roleName, Timestamp timestamp) {

        for (DomainRoleMember member : members) {
            if (member.getMemberName().equals(memberName)) {
                for (MemberRole memberRole : member.getMemberRoles()) {
                    if (memberRole.getRoleName().equals(roleName)) {
                        return memberRole.getExpiration().equals(timestamp);
                    }
                }
            }
        }

        return false;
    }
}
