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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.shaded.org.apache.commons.io.FileUtils;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.testng.Assert.assertEquals;

public class ZMSTestUtils {

    private static final Logger LOG = LoggerFactory.getLogger(ZMSTestUtils.class);

    public static MySQLContainer startMemoryMySQL(final String userName, final String password) {

        System.out.println("Starting MySQL server using testcontainers...");
        MySQLContainer<?> mysql = null;
        try {

            String externalInitScriptPath = "schema/zms_server.sql";
            File destinationInitScript = new File("src/test/resources/mysql/zms_server.sql");
            FileUtils.copyFile(new File(externalInitScriptPath), destinationInitScript);
            LOG.info("Copied {} to {}", externalInitScriptPath, destinationInitScript.getAbsolutePath());

            mysql = new MySQLContainer<>(DockerImageName.parse("mysql/mysql-server:5.7").asCompatibleSubstituteFor("mysql"))
                    .withDatabaseName("zms_server")
                    .withUsername(userName)
                    .withPassword(password)
                    .withEnv("MYSQL_ROOT_PASSWORD", password)
                    .withInitScript("mysql/zms_server.sql")
                    .withStartupTimeout(Duration.ofMinutes(1))
                    .withCopyFileToContainer(
                            MountableFile.forClasspathResource("mysql/"),
                            "/athenz-mysql-scripts/");
            mysql.start();
            mysql.followOutput(new Slf4jLogConsumer(LOG));
        } catch (Throwable t) {
            LOG.error("Unable to start MySQL server using testcontainers", t);
        }

        return mysql;
    }

    public static void stopMemoryMySQL(MySQLContainer<?> mysqld) {
        System.out.println("Stopping testcontainers MySQL server...");
        mysqld.stop();
    }

    public static void setDatabaseReadOnlyMode(MySQLContainer<?> mysqld, boolean readOnly, final String username, final String password) throws IOException, InterruptedException {
        final String scriptName = readOnly ? "set-read-only.sql" : "unset-read-only.sql";
        try {
            mysqld.execInContainer("mysql", "-u", "root", "-p"+password, "zms_server", "-e", "source /athenz-mysql-scripts/" + scriptName);
        } catch (Throwable t) {
            LOG.error("Unable to execute script in testcontainers mysql container: " + scriptName, t);
        }

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
            final String memberName, final String roleName, Timestamp timestamp,
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

        UserList userList = zms.getUserList(ctx, null);
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
        return Timestamp.fromMillis(date.millis() + TimeUnit.MILLISECONDS.convert(days, TimeUnit.DAYS));
    }

    public static boolean validateDueDate(long millis, long extMillis) {
        return (millis > System.currentTimeMillis() + extMillis - 5000 && millis < System.currentTimeMillis() + extMillis + 5000);
    }

    public static Timestamp buildExpiration(int daysInterval, boolean alreadyExpired) {
        return Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(alreadyExpired ? -daysInterval : daysInterval , TimeUnit.DAYS));
    }

    public static void assertChange(DomainChangeMessage change, DomainChangeMessage.ObjectType objType,
            final String domainName, final String objName, final String apiName) {
        assertEquals(change.getObjectType(), objType);
        assertEquals(change.getDomainName(), domainName);
        assertEquals(change.getObjectName(), objName);
        assertEquals(change.getApiName(), apiName.toLowerCase());
    }

    public static RoleMeta createRoleMetaObject(Boolean selfServe) {

        RoleMeta meta = new RoleMeta();

        if (selfServe != null) {
            meta.setSelfServe(selfServe);
        }
        return meta;
    }

    public static RoleSystemMeta createRoleSystemMetaObject(Boolean auditEnabled) {

        RoleSystemMeta meta = new RoleSystemMeta();

        if (auditEnabled != null) {
            meta.setAuditEnabled(auditEnabled);
        }
        return meta;
    }
}
