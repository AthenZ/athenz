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

import com.wix.mysql.EmbeddedMysql;
import com.wix.mysql.Sources;
import com.wix.mysql.SqlScriptSource;
import com.wix.mysql.config.MysqldConfig;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
import org.testng.internal.junit.ArrayAsserts;

import java.io.File;
import java.util.Calendar;
import java.util.List;
import java.util.function.Function;

import static com.wix.mysql.EmbeddedMysql.anEmbeddedMysql;
import static com.wix.mysql.ScriptResolver.classPathScript;
import static com.wix.mysql.config.MysqldConfig.aMysqldConfig;
import static com.wix.mysql.distribution.Version.v5_7_latest;
import static org.testng.AssertJUnit.assertEquals;

public class ZMSTestUtils {

    public static EmbeddedMysql startMemoryMySQL(final String userName, final String password) {

        System.out.println("Starting Embedded MySQL server...");

        final MysqldConfig config = aMysqldConfig(v5_7_latest)
                .withPort(3310)
                .withUser(userName, password)
                .build();

        File sqlSchemaFile = new File("schema/zms_server.sql");
        return anEmbeddedMysql(config)
                .addSchema("zms_server", Sources.fromFile(sqlSchemaFile))
                .start();
    }

    public static void stopMemoryMySQL(EmbeddedMysql mysqld) {
        System.out.println("Stopping Embedded MySQL server...");
        mysqld.stop();
    }

    public static void setDatabaseReadOnlyMode(EmbeddedMysql mysqld, boolean readOnly) {
        final String scriptName = readOnly ? "mysql/set-read-only.sql" : "mysql/unset-read-only.sql";
        mysqld.executeScripts("zms_server", classPathScript(scriptName));
    }

    public static boolean verifyDomainRoleMember(DomainRoleMember domainRoleMember, MemberRole memberRole) {
        for (MemberRole mbrRole : domainRoleMember.getMemberRoles()) {
            if (mbrRole.equals(memberRole)) {
                return true;
            }
        }
        return false;
    }

    public static boolean verifyDomainRoleMember(List<DomainRoleMember> members, String memberName,
            String... roles) {

        for (DomainRoleMember member : members) {
            if (member.getMemberName().equals(memberName)) {
                List<MemberRole> memberRoles = member.getMemberRoles();
                if (memberRoles.size() != roles.length) {
                    return false;
                }
                for (String role : roles) {
                    boolean bMatchFound = false;
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

    public static boolean verifyDomainRoleMemberTimestamp(List<DomainRoleMember> members,
                                                          String memberName,
                                                          String roleName,
                                                          Timestamp timestamp,
                                                          Function<MemberRole, Timestamp> timestampGetter) {

        for (DomainRoleMember member : members) {
            if (member.getMemberName().equals(memberName)) {
                for (MemberRole memberRole : member.getMemberRoles()) {
                    if (memberRole.getRoleName().equals(roleName)) {
                        return timestampGetter.apply(memberRole).equals(timestamp);
                    }
                }
            }
        }

        return false;
    }

    public static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            //ignored
        }
    }

    public static Domain makeDomainObject(final String domainName, final String description,
            final String org, Boolean auditEnabled, final String account,
            int productId, String applicationId, Integer expiryDays) {

        return new Domain().setName(domainName).setDescription(description).setOrg(org)
                .setAuditEnabled(auditEnabled).setAccount(account).setYpmId(productId)
                .setApplicationId(applicationId).setMemberExpiryDays(expiryDays)
                .setId(UUID.fromCurrentTime()).setModified(Timestamp.fromCurrentTime());
    }

    public static void cleanupNotAdminUsers(ZMSImpl zms, final String adminUser, ResourceContext ctx) {

        UserList userList = zms.getUserList(ctx);
        List<String> users = userList.getNames();
        for (String user : users) {
            if (user.equals(adminUser)) {
                continue;
            }
            if (!user.startsWith("user.") || user.contains("*")) {
                continue;
            }
            zms.deleteUser(ctx, user.substring(5), "audit-ref");
        }
    }

    public static Timestamp addDays(Timestamp date, int days) {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(date.millis());
        cal.add(Calendar.DATE, days);
        return Timestamp.fromMillis(cal.getTime().getTime());
    }
}
