package com.yahoo.athenz.zms;

import com.yahoo.rdl.Timestamp;
import org.testng.Assert;
import org.testng.annotations.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.zms.ZMSConsts.DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT;

public class PurgeExpiredMembersTest {
    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clear() {
        zmsTestInitializer.clearConnections();
        System.clearProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_MAX_DB_CALLS_PER_RUN);
        System.clearProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_LIMIT_PER_CALL);
    }

    private Timestamp buildExpiration(int daysInterval) {
       return Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(daysInterval, TimeUnit.DAYS));
    }

    private RoleMember createRoleMemberWithExpiration(String name, boolean alreadyExpired, int expiryDaysInterval) {
        return new RoleMember()
                .setMemberName(name)
                .setExpiration(buildExpiration(alreadyExpired ?  - expiryDaysInterval : expiryDaysInterval));
    }

    private GroupMember createExpiredGroupMember(String name, boolean alreadyExpired, int expiryDays) {
        return new GroupMember()
                .setMemberName(name)
                .setExpiration(buildExpiration(alreadyExpired ?  - expiryDays : expiryDays));
    }

    private long getDaysSinceExpiry(Timestamp expiry) {
        Date expirationDate = new Date(expiry.millis());
        Date date = new Date();
        long diffInMillis = date.getTime() - expirationDate.getTime();
        return TimeUnit.DAYS.convert(diffInMillis, TimeUnit.MILLISECONDS);
    }

    private void insertRoleMembersToDB (ZMSImpl zms, ResourceContext ctx, int memberPurgeExpiryDays, String auditRef) {
        TopLevelDomain purgeExpiryDaysDom = zmsTestInitializer.createTopLevelDomainObject("test-domain1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), memberPurgeExpiryDays);
        zms.postTopLevelDomain(ctx, auditRef, purgeExpiryDaysDom);
        List <RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(createRoleMemberWithExpiration("user.test1", true, memberPurgeExpiryDays - 1));
        roleMembers.add(createRoleMemberWithExpiration("user.test2", true, memberPurgeExpiryDays));
        roleMembers.add(createRoleMemberWithExpiration("user.test3", true, memberPurgeExpiryDays + 1));
        Role role1 = zmsTestInitializer.createRoleObject("test-domain1", "role1", null, roleMembers);
        zms.putRole(ctx,"test-domain1", "role1", auditRef, role1);

        TopLevelDomain defaultPurgeExpiryDaysDom = zmsTestInitializer.createTopLevelDomainObject("test-domain2",
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zms.postTopLevelDomain(ctx, auditRef, defaultPurgeExpiryDaysDom);
        List <RoleMember> roleMembers2 = new ArrayList<>();
        roleMembers2.add(createRoleMemberWithExpiration("user.test4", true, DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - 1));
        roleMembers2.add(createRoleMemberWithExpiration("user.test5",  true, DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT));
        roleMembers2.add(createRoleMemberWithExpiration("user.test6", true, DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT + 1));
        roleMembers2.add(createRoleMemberWithExpiration("user.test7", false, 1));
        Role role2 = zmsTestInitializer.createRoleObject("test-domain2", "role2", null, roleMembers2);
        zms.putRole(ctx,"test-domain2", "role2", auditRef, role2);
    }

    @Test
    public void purgeExpiredRoleMembersTest() {
        ZMSImpl zms =  zmsTestInitializer.getZms();
        ResourceContext ctx  = zmsTestInitializer.getMockDomRsrcCtx();
        String auditRef = "purge expired members test";
        int memberPurgeExpiryDays = 100;
        insertRoleMembersToDB(zms, ctx, memberPurgeExpiryDays, auditRef);

        zms.dbService.executeDeleteAllExpiredRoleMemberships(ctx, auditRef, "test");

        Role role;
        long DaysSinceExpiry;

        role = zms.dbService.getRole("test-domain1", "role1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE);
        Assert.assertEquals(role.roleMembers.size(), 1);
        Assert.assertEquals(role.roleMembers.get(0).memberName, "user.test1");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(0).expiration);
        Assert.assertTrue(memberPurgeExpiryDays - DaysSinceExpiry > 0);

        role = zms.dbService.getRole("test-domain2", "role2", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE);
        Assert.assertEquals(role.roleMembers.size(), 2);
        Assert.assertEquals(role.roleMembers.get(0).memberName, "user.test4");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(0).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);
        Assert.assertEquals(role.roleMembers.get(1).memberName, "user.test7");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(1).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);

        zms.deleteTopLevelDomain(ctx,"test-domain1", auditRef);
        zms.deleteTopLevelDomain(ctx,"test-domain2", auditRef);
    }

    @Test
    public void purgeExpiredRoleMembersAdditionalCallTest() {
        System.setProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_LIMIT_PER_CALL, "2");
        ZMSImpl zms =  zmsTestInitializer.getZms();
        ResourceContext ctx  = zmsTestInitializer.getMockDomRsrcCtx();
        String auditRef = "purge expired members test";
        int memberPurgeExpiryDays = 100;
        insertRoleMembersToDB(zms, ctx, memberPurgeExpiryDays, auditRef);

        zms.dbService.executeDeleteAllExpiredRoleMemberships(ctx, auditRef, "test");

        Role role;
        long DaysSinceExpiry;

        role = zms.dbService.getRole("test-domain1", "role1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE);
        Assert.assertEquals(role.roleMembers.size(), 1);
        Assert.assertEquals(role.roleMembers.get(0).memberName, "user.test1");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(0).expiration);
        Assert.assertTrue(memberPurgeExpiryDays - DaysSinceExpiry > 0);

        role = zms.dbService.getRole("test-domain2", "role2", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE);
        Assert.assertEquals(role.roleMembers.size(), 2);
        Assert.assertEquals(role.roleMembers.get(0).memberName, "user.test4");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(0).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);
        Assert.assertEquals(role.roleMembers.get(1).memberName, "user.test7");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(1).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);

        zms.deleteTopLevelDomain(ctx,"test-domain1", auditRef);
        zms.deleteTopLevelDomain(ctx,"test-domain2", auditRef);
    }

    @Test
    public void purgeExpiredRoleMembersDoesntRemoveAllTest() {
        System.setProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_LIMIT_PER_CALL, "3");
        System.setProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_MAX_DB_CALLS_PER_RUN, "1");
        ZMSImpl zms =  zmsTestInitializer.getZms();
        ResourceContext ctx  = zmsTestInitializer.getMockDomRsrcCtx();
        String auditRef = "purge expired members test";
        int memberPurgeExpiryDays = 100;
        insertRoleMembersToDB(zms, ctx, memberPurgeExpiryDays, auditRef);

        zms.dbService.executeDeleteAllExpiredRoleMemberships(ctx, auditRef, "test");

        Role role;
        long DaysSinceExpiry;

        role = zms.dbService.getRole("test-domain1", "role1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE);
        Assert.assertEquals(role.roleMembers.size(), 1);
        Assert.assertEquals(role.roleMembers.get(0).memberName, "user.test1");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(0).expiration);
        Assert.assertTrue(memberPurgeExpiryDays - DaysSinceExpiry > 0);

        role = zms.dbService.getRole("test-domain2", "role2", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE);
        Assert.assertEquals(role.roleMembers.size(), 3);
        Assert.assertEquals(role.roleMembers.get(0).memberName, "user.test4");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(0).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);
        Assert.assertEquals(role.roleMembers.get(1).memberName, "user.test6");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(1).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry < 0);
        Assert.assertEquals(role.roleMembers.get(2).memberName, "user.test7");
        DaysSinceExpiry = getDaysSinceExpiry(role.roleMembers.get(2).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);

        zms.deleteTopLevelDomain(ctx,"test-domain1", auditRef);
        zms.deleteTopLevelDomain(ctx,"test-domain2", auditRef);
    }

    private void insertGroupMembersToDB (ZMSImpl zms, ResourceContext ctx, int memberPurgeExpiryDays, String auditRef) {
        TopLevelDomain purgeExpiryDaysDom = zmsTestInitializer.createTopLevelDomainObject("test-domain1",
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), memberPurgeExpiryDays);
        zms.postTopLevelDomain(ctx, auditRef, purgeExpiryDaysDom);

        List <GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(createExpiredGroupMember("user.test1", true, memberPurgeExpiryDays - 1));
        groupMembers.add(createExpiredGroupMember("user.test2", true, memberPurgeExpiryDays));
        groupMembers.add(createExpiredGroupMember("user.test3", true, memberPurgeExpiryDays + 1));
        Group group1 = zmsTestInitializer.createGroupObject("test-domain1", "group1", groupMembers);
        zms.putGroup(ctx,"test-domain1", "group1", auditRef, group1);

        TopLevelDomain defaultPurgeExpiryDaysDom = zmsTestInitializer.createTopLevelDomainObject("test-domain2",
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zms.postTopLevelDomain(ctx, auditRef, defaultPurgeExpiryDaysDom);
        List <GroupMember> groupMembers2 = new ArrayList<>();
        groupMembers2.add(createExpiredGroupMember("user.test4", true, DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - 1));
        groupMembers2.add(createExpiredGroupMember("user.test5", true,  DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT));
        groupMembers2.add(createExpiredGroupMember("user.test6", true, DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT + 1));
        groupMembers2.add(createExpiredGroupMember("user.test7", false, 1));
        Group group2 = zmsTestInitializer.createGroupObject("test-domain2", "group2", groupMembers2);
        zms.putGroup(ctx,"test-domain2", "group2", auditRef, group2);
    }

    @Test
    public void purgeExpiredGroupMembersTest() {
        ZMSImpl zms =  zmsTestInitializer.getZms();
        ResourceContext ctx  = zmsTestInitializer.getMockDomRsrcCtx();
        String auditRef = "purge expired members test";
        int memberPurgeExpiryDays = 100;

        insertGroupMembersToDB(zms, ctx, memberPurgeExpiryDays, auditRef);

        zms.dbService.executeDeleteAllExpiredGroupMemberships(ctx, auditRef, "test");

        Group group;
        long DaysSinceExpiry;

        group = zms.dbService.getGroup("test-domain1", "group1", Boolean.FALSE, Boolean.FALSE);
        Assert.assertEquals(group.getGroupMembers().size(), 1);
        Assert.assertEquals(group.getGroupMembers().get(0).memberName, "user.test1");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(0).expiration);
        Assert.assertTrue(memberPurgeExpiryDays - DaysSinceExpiry > 0);

        group = zms.dbService.getGroup("test-domain2", "group2", Boolean.FALSE, Boolean.FALSE);
        Assert.assertEquals(group.getGroupMembers().size(), 2);
        Assert.assertEquals(group.getGroupMembers().get(0).memberName, "user.test4");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(0).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);
        Assert.assertEquals(group.getGroupMembers().get(1).memberName, "user.test7");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(1).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);

        zms.deleteTopLevelDomain(ctx,"test-domain1", auditRef);
        zms.deleteTopLevelDomain(ctx,"test-domain2", auditRef);
    }

    @Test
    public void purgeExpiredGroupMembersAdditionalCallTest() {
        System.setProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_LIMIT_PER_CALL, "3");
        ZMSImpl zms =  zmsTestInitializer.getZms();
        ResourceContext ctx  = zmsTestInitializer.getMockDomRsrcCtx();
        String auditRef = "purge expired members test";
        int memberPurgeExpiryDays = 100;

        insertGroupMembersToDB(zms, ctx, memberPurgeExpiryDays, auditRef);

        zms.dbService.executeDeleteAllExpiredGroupMemberships(ctx, auditRef, "test");

        Group group;
        long DaysSinceExpiry;

        group = zms.dbService.getGroup("test-domain1", "group1", Boolean.FALSE, Boolean.FALSE);
        Assert.assertEquals(group.getGroupMembers().size(), 1);
        Assert.assertEquals(group.getGroupMembers().get(0).memberName, "user.test1");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(0).expiration);
        Assert.assertTrue(memberPurgeExpiryDays - DaysSinceExpiry > 0);

        group = zms.dbService.getGroup("test-domain2", "group2", Boolean.FALSE, Boolean.FALSE);
        Assert.assertEquals(group.getGroupMembers().size(), 2);
        Assert.assertEquals(group.getGroupMembers().get(0).memberName, "user.test4");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(0).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);
        Assert.assertEquals(group.getGroupMembers().get(1).memberName, "user.test7");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(1).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);

        zms.deleteTopLevelDomain(ctx,"test-domain1", auditRef);
        zms.deleteTopLevelDomain(ctx,"test-domain2", auditRef);
    }

    @Test
    public void purgeExpiredGroupMembersDoesntDeleteAllTest() {
        System.setProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_LIMIT_PER_CALL, "3");
        System.setProperty(ZMSConsts.ZMS_PROP_PURGE_TASK_MAX_DB_CALLS_PER_RUN, "1");
        ZMSImpl zms =  zmsTestInitializer.getZms();
        ResourceContext ctx  = zmsTestInitializer.getMockDomRsrcCtx();
        String auditRef = "purge expired members test";
        int memberPurgeExpiryDays = 100;

        insertGroupMembersToDB(zms, ctx , memberPurgeExpiryDays, auditRef);

        zms.dbService.executeDeleteAllExpiredGroupMemberships(ctx, auditRef, "test");

        Group group;
        long DaysSinceExpiry;

        group = zms.dbService.getGroup("test-domain1", "group1", Boolean.FALSE, Boolean.FALSE);
        Assert.assertEquals(group.getGroupMembers().size(), 1);
        Assert.assertEquals(group.getGroupMembers().get(0).memberName, "user.test1");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(0).expiration);
        Assert.assertTrue(memberPurgeExpiryDays - DaysSinceExpiry > 0);

        group = zms.dbService.getGroup("test-domain2", "group2", Boolean.FALSE, Boolean.FALSE);
        Assert.assertEquals(group.getGroupMembers().size(), 3);
        Assert.assertEquals(group.getGroupMembers().get(0).memberName, "user.test4");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(0).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry > 0);
        Assert.assertEquals(group.getGroupMembers().get(1).memberName, "user.test6");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(1).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry < 0);
        Assert.assertEquals(group.getGroupMembers().get(2).memberName, "user.test7");
        DaysSinceExpiry = getDaysSinceExpiry(group.getGroupMembers().get(2).expiration);
        Assert.assertTrue(DELAY_PURGE_EXPIRED_MEMBERS_DAYS_DEFAULT - DaysSinceExpiry >= 0);

        zms.deleteTopLevelDomain(ctx,"test-domain1", auditRef);
        zms.deleteTopLevelDomain(ctx,"test-domain2", auditRef);
    }
}
