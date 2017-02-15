/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.common.server.log.impl;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Pattern;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder;
import com.yahoo.rdl.*;

/**
 * Test all API of AuditLogMsgBuilder.
 * Test the getMsgBuilder() API of AuditLogFactory.
 */
public class AuditLogMsgBuilderTest {

    private static final String ZMS_USER_DOMAIN = "athenz.user_domain";
    private static final String USER_DOMAIN = System.getProperty(ZMS_USER_DOMAIN, "user");
    
    static String TOKEN_STR = "v=U1;d=" + USER_DOMAIN + ";n=roger;h=somehost.somecompany.com;a=666;t=1492;e=2493;s=signature;";

    static Array assertsOrig = null;
    static Array assertsNew  = null;

    DefaultAuditLogMsgBuilder starter(final String whatApi) {
        AuditLogMsgBuilder msgBldr = AuditLogFactory.getMsgBuilder();
        msgBldr.who(TOKEN_STR).when(Timestamp.fromCurrentTime()).clientIp("12.12.12.12").whatApi(whatApi);
        return (DefaultAuditLogMsgBuilder)msgBldr;
    }
    
    Struct setupEntity(final String [] keys, final Object [] vals) {
        Struct entity = new Struct().with(keys[0], vals[0]);
        for (int cnt = 1; cnt < keys.length; ++cnt) {
            entity.with(keys[cnt], vals[cnt]);
        }
        return entity;
    }
    
    @BeforeClass
    public static synchronized void setUp() throws Exception {
        Struct assert1 = new Struct().with("role", "worker").with("resource", "potatoes").with("action", "eat");
        Struct assert2 = new Struct().with("role", "worker").with("resource", "yams").with("action", "eat");
        Struct assert3 = new Struct().with("role", "child").with("resource", "cereal").with("action", "slurp");
        assertsOrig = new Array().with(assert1).with(assert2).with(assert3);
        
        Struct assert1n = new Struct().with("role", "worker").with("resource", "apples").with("action", "eat");
        Struct assert2n = new Struct().with("role", "worker").with("resource", "yams").with("action", "eat");
        Struct assert3n = new Struct().with("role", "child").with("resource", "cereal").with("action", "chomp");
        assertsNew = new Array().with(assert1n).with(assert2n).with(assert3n);
    }
    
    @Test
    public void testGetMsgBuilderClassName() {
        String auditLogMsgBuilderClassName = "com.yahoo.athenz.common.server.log.impl.TestMsgBuilder";
        try {
            AuditLogMsgBuilder msgBldr = AuditLogFactory.getMsgBuilder(auditLogMsgBuilderClassName);
            String dataStr = "getMsgBuilder";
            msgBldr.whatApi(dataStr);
            Assert.assertTrue(msgBldr.whatApi().equals(dataStr), "whatApi string=" + msgBldr.whatApi());
            dataStr = msgBldr.getClass().getName();
            Assert.assertTrue(dataStr.equals(auditLogMsgBuilderClassName), "classname=" + dataStr);
        } catch (Exception exc) {
            Assert.fail("Should have created the AuditLogMsgBuilder=TestMsgBuilder", exc);
        }
    }

    @Test
    public void testWho() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWho");
        String dataStr = "me?";
        msgBldr.who(dataStr);
        Assert.assertTrue(msgBldr.who().equals(dataStr), "who string=" + msgBldr.who());
    }
    
    @Test
    public void testWhy() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhy");
        String dataStr = "not?";
        msgBldr.why(dataStr);
        Assert.assertTrue(msgBldr.why().equals(dataStr), "why string=" + msgBldr.why());
    }

    @Test
    public void testWhenTimestamp() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhenTimestamp");
        Timestamp ts = Timestamp.fromCurrentTime();
        msgBldr.when(ts);
        String dataStr = ts.toString();
        Assert.assertTrue(msgBldr.when().equals(dataStr), "when string=" + msgBldr.when());
    }

    @Test
    public void testWhenString() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhenString");
        String dataStr = "now?";
        msgBldr.when(dataStr);
        Assert.assertTrue(msgBldr.when().equals(dataStr), "when string=" + msgBldr.when());
    }

    @Test
    public void testClientIp() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testClientIp");
        String dataStr = "99.77.22.hup";
        msgBldr.clientIp(dataStr);
        Assert.assertTrue(msgBldr.clientIp().equals(dataStr), "clientIp string=" + msgBldr.clientIp());
    }

    @Test
    public void testWhereIp() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhereIp");
        String dataStr = "128.33.42.76";
        msgBldr.whereIp(dataStr);
        Assert.assertTrue(msgBldr.where().contains("server-ip=" + dataStr), "whereIp string=" + msgBldr.where());
    }
    
    @Test
    public void testWhereHttpsPort() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhereHttpsPort");
        String dataStr = "4443";
        msgBldr.whereHttpsPort(dataStr);
        Assert.assertTrue(msgBldr.where().contains("server-https-port=" + dataStr), "whereHttpsPort string=" + msgBldr.where());
    }

    @Test
    public void testWhereHttpPort() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhereHttpPort");
        String dataStr = "80";
        msgBldr.whereHttpPort(dataStr);
        Assert.assertTrue(msgBldr.where().contains("server-http-port=" + dataStr), "whereHttpPort string=" + msgBldr.where());
    }
    
    @Test
    public void testWhereIpPortHttpsPort() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhereIpPortHttpsPort");
        String ipStr = "128.33.42.76";
        msgBldr.whereIp(ipStr);
        String httpsPortStr = "4443";
        msgBldr.whereHttpsPort(httpsPortStr);
        String httpPortStr = "80";
        msgBldr.whereHttpPort(httpPortStr);
        
        Assert.assertTrue(msgBldr.where().contains("server-ip=" + ipStr), "where string=" + msgBldr.where());
        Assert.assertTrue(msgBldr.where().contains("server-https-port=" + httpsPortStr), "where string=" + msgBldr.where());
        Assert.assertTrue(msgBldr.where().contains("server-http-port=" + httpPortStr), "where string=" + msgBldr.where());
    }

    @Test
    public void testWhatMethod() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatMethod");
        String dataStr = "PUT";
        msgBldr.whatMethod(dataStr);
        Assert.assertTrue(msgBldr.whatMethod().equals(dataStr), "whatMethod string=" + msgBldr.whatMethod());
    }

    @Test
    public void testWhatApi() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatApi");
        String dataStr = "putRole";
        msgBldr.whatApi(dataStr);
        Assert.assertTrue(msgBldr.whatApi().equals(dataStr), "whatApi string=" + msgBldr.whatApi());
    }

    @Test
    public void testWhatDomain() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDomain");
        String dataStr = "sys.auth";
        msgBldr.whatDomain(dataStr);
        Assert.assertTrue(msgBldr.whatDomain().equals(dataStr), "whatDomain string=" + msgBldr.whatDomain());
    }

    @Test
    public void testWhatEntity() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatEntity");
        String dataStr = "readers";
        msgBldr.whatEntity(dataStr);
        Assert.assertTrue(msgBldr.whatEntity().equals(dataStr), "whatEntity string=" + msgBldr.whatEntity());
    }

    /**
     * Test method for {@link com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder#buildDiffKeys(java.util.Set, com.yahoo.data.Struct, java.lang.StringBuilder)}.
     */
    @Test
    public void testBuildDiffKeys() {
        String []keyNames = new String[] { "alpha", "beta" };
        String []vals     = new String[] { "Apple", "Banana" };
        Struct entity = setupEntity(keyNames, vals);
        Set<String> keys = entity.keySet();

        DefaultAuditLogMsgBuilder msgBldr = starter("testBuildDiffKeys");
        StringBuilder sb = new StringBuilder("");
        msgBldr.buildDiffKeys(keys, entity, sb);
        String diff = sb.toString();
        Assert.assertTrue(diff.contains("alpha=\"Apple\""), "Test string=" + diff);
        Assert.assertTrue(diff.contains("beta=\"Banana\""), "Test string=" + diff);
    }
    
    @Test
    public void testBuildDiffValueSet() {

        String []svals = new String[] { "Apple", "Banana", "PawPaw" };
        List<String> vals  = Arrays.asList( svals );
        Set<String> valSet = new HashSet<String>(vals);
        
        DefaultAuditLogMsgBuilder msgBldr = starter("testBuildDiffValueSet");
        StringBuilder sb = new StringBuilder("");
        msgBldr.buildDiffValueSet(valSet, sb);
        String diff = sb.toString();
        Assert.assertTrue(diff.contains("Apple") && diff.contains("Banana") && diff.contains("PawPaw"), "Test string=" + diff);
    }
    
    @Test
    public void testBuildDiffArray() {

        DefaultAuditLogMsgBuilder msgBldr = starter("testBuildArrayDiff");
        StringBuilder addedSetSb   = new StringBuilder();
        StringBuilder removedSetSb = new StringBuilder();
        msgBldr.buildDiffArray(assertsOrig, assertsNew, addedSetSb, removedSetSb);
        
        // Added-str={role: "child", resource: "cereal", action: "chomp"},{role: "worker", resource: "apples", action: "eat"}
        // Removed-str={role: "worker", resource: "potatoes", action: "eat"},{role: "child", resource: "cereal", action: "slurp"}
        boolean match = addedSetSb.indexOf("child") != -1 && 
                addedSetSb.indexOf("cereal") != -1 && addedSetSb.indexOf("chomp") != -1 &&
                addedSetSb.indexOf("slurp") == -1;
        Assert.assertTrue(match, "Added-str for child=" + addedSetSb);
        match = addedSetSb.indexOf("worker") != -1 && 
                addedSetSb.indexOf("apples") != -1 && addedSetSb.indexOf("eat") != -1 &&
                addedSetSb.indexOf("yams") == -1;
        Assert.assertTrue(match, "Added-str for worker=" + addedSetSb);
        
        match = removedSetSb.indexOf("child") != -1 && 
                removedSetSb.indexOf("cereal") != -1 && removedSetSb.indexOf("slurp") != -1 &&
                        removedSetSb.indexOf("chomp") == -1;
        Assert.assertTrue(match, "Removed-str for child=" + removedSetSb);
        match = removedSetSb.indexOf("worker") != -1 && 
                removedSetSb.indexOf("potatoes") != -1 && removedSetSb.indexOf("eat") != -1 &&
                        removedSetSb.indexOf("yams") == -1;
        Assert.assertTrue(match, "Removed-str for worker=" + removedSetSb);
    }
    
    @Test
    public void testWhatSubDetailsEntityStruct() {
        // test Struct inside of Struct
        // Entity from ZMS schema: contains 'name' as String and 'value' as Struct
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDetailsEntityStruct");
        Struct origValue = new Struct().with("field", "of_dreams").with("champ", "de_reve").with("same", "thing");
        Struct newValue  = new Struct().with("field", "hockey").with("champ", "bailey").with("same", "thing");
        String [] origKeys = new String[] { "name", "value" };
        Object [] origVals = new Object[] { "policyAlpha", origValue };
        String [] newKeys  = new String[] { "name", "value" };
        Object [] newVals  = new Object[] { "policyAlpha", newValue };
        Struct origFields  = setupEntity(origKeys, origVals);
        Struct newFields   = setupEntity(newKeys, newVals);
        
        String details = msgBldr.whatSubDetails("entity", origFields, newFields);
        // details=entity=(
        //   CHANGED=(
        //     value=(
        //       CHANGED=(
        //         field=(FROM=(of_dreams);TO=(hockey));
        //         champ=(FROM=(de_reve);TO=(bailey)););
        //      REMOVED=(null);
        //      ADDED=(null);));
        //   REMOVED=(null);
        //   ADDED=(null);)
        
        int drindex = details.indexOf("field=(FROM=(of_dreams);TO=(hockey))");
        Assert.assertTrue(drindex != -1, "dreams-index=" + drindex + " details=" + details);
        
        int rindex = details.indexOf("champ=(FROM=(de_reve);TO=(bailey))");
        Assert.assertTrue(rindex != -1, "de_reve-index=" + rindex + " details=" + details);
    }
    
    @Test
    public void testWhatDetailsNoChanges() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDetails");
        String [] origKeys = new String[] { "alpha", "beta", "gamma" };
        String [] origVals = new String[] { "Aval", "Bval", "Gval" };
        String [] newKeys  = new String[] { "alpha", "beta", "gamma" };
        String [] newVals  = new String[] { "Aval", "Bval", "Gval" };
        Struct origFields  = setupEntity(origKeys, origVals);
        Struct newFields   = setupEntity(newKeys, newVals);
        msgBldr.whatDetails("Bsame", origFields, newFields);
        
        String msg = msgBldr.whatDetails();
        Assert.assertTrue(msg.contains("CHANGED=(null)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("REMOVED=(null)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("ADDED=(null)"), "Test string=" + msg);
    }
    
    @Test
    public void testWhatDetailsAdded() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDetails");
        String [] origKeys = new String[] { "alpha", "beta", "gamma" };
        String [] origVals = new String[] { "Aval", "Bval", "Gval" };
        String [] newKeys  = new String[] { "alpha", "beta", "gamma", "delta" };
        String [] newVals  = new String[] { "Aval", "Bval", "Gval", "Dval" };
        Struct origFields  = setupEntity(origKeys, origVals);
        Struct newFields   = setupEntity(newKeys, newVals);
        msgBldr.whatDetails("Bsame", origFields, newFields);
        
        String msg = msgBldr.whatDetails();
        Assert.assertTrue(msg.contains("CHANGED=(null)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("REMOVED=(null)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("ADDED=(delta=\"Dval\")"), "Test string=" + msg);
    }
    
    @Test
    public void testWhatDetailsRemoved() {
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDetails");
        String [] origKeys = new String[] { "alpha", "beta", "gamma" };
        String [] origVals = new String[] { "Aval", "Bval", "Gval" };
        String [] newKeys  = new String[] { "alpha", "gamma" };
        String [] newVals  = new String[] { "Aval", "Gval" };
        Struct origFields  = setupEntity(origKeys, origVals);
        Struct newFields   = setupEntity(newKeys, newVals);
        msgBldr.whatDetails("Bsame", origFields, newFields);
        
        String msg = msgBldr.whatDetails();
        Assert.assertTrue(msg.contains("CHANGED=(null)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("REMOVED=(beta=\"Bval\")"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("ADDED=(null)"), "Test string=" + msg);
    }
    
    /**
     * Test method for {@link com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder#whatDetails(java.lang.String, com.yahoo.data.Struct, com.yahoo.data.Struct)}.
     */
    @Test
    public void testWhatDetailsChangedRemovedAdded() {
        AuditLogMsgBuilder msgBldr = starter("testWhatDetailsChangedRemovedAdded");
        
        String [] origKeys = new String[] { "alpha", "beta", "gamma" };
        String [] origVals = new String[] { "Aval", "Bval", "Gval" };
        String [] newKeys  = new String[] { "beta", "gamma", "delta" };
        String [] newVals  = new String[] { "Bval", "Gammaval", "Dval" };
        Struct origFields  = setupEntity(origKeys, origVals);
        Struct newFields   = setupEntity(newKeys, newVals);
        msgBldr.whatDetails("Bsame", origFields, newFields);
        
        String msg = msgBldr.whatDetails();
        Assert.assertTrue(msg.contains("gamma=(FROM=(Gval);TO=(Gammaval))"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("REMOVED=(alpha=\"Aval\")"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("ADDED=(delta=\"Dval\")"), "Test string=" + msg);
    }
    
    @Test
    public void testWhatDetailsPolicyStructs() {
        // test Array inside of Struct
        // Policy from ZMS schema: contains 'name' as String, 'modified' as Timestamp,
        //    'assertions' as Array of Struct
        DefaultAuditLogMsgBuilder msgBldr = starter("testWhatDetailsPolicyStructs");
        Timestamp tsOrig = Timestamp.fromCurrentTime();
        long millis = tsOrig.millis() + 1000;
        Timestamp tsNew = Timestamp.fromMillis(millis);
        String [] origKeys = new String[] { "name", "modified", "assertions" };
        Object [] origVals = new Object[] { "policyAlpha", tsOrig, assertsOrig };
        String [] newKeys  = new String[] { "name", "modified", "assertions" };
        Object [] newVals  = new Object[] { "policyAlpha", tsNew, assertsNew };
        Struct origFields  = setupEntity(origKeys, origVals);
        Struct newFields   = setupEntity(newKeys, newVals);
        msgBldr.whatDetails("policies", origFields, newFields);
        
        String details = msgBldr.whatDetails();
        // details=policies=
        //  (CHANGED=
        //    (ADDED-VALUES=
        //      ({role: "child", resource: "cereal", action: "chomp"},{role: "worker", resource: "apples", action: "eat"});
        //     REMOVED-VALUES=({role: "child", resource: "cereal", action: "slurp"},{role: "worker", resource: "potatoes", action: "eat"});
        //    (FROM=(null);
        //     TO=(null););
        //  REMOVED=(null);
        //  ADDED=(null);)
        int aindex = details.indexOf("ADDED-VALUES=(");
        Assert.assertTrue(aindex != -1, "details=" + details);
        int rindex = details.indexOf("REMOVED-VALUES=(");
        Assert.assertTrue(rindex != -1, "details=" + details);
        
        int addedVals = details.indexOf("chomp", aindex);
        Assert.assertTrue(addedVals != -1 && addedVals < rindex, "details=" + details);
        addedVals = details.indexOf("apples", aindex);
        Assert.assertTrue(addedVals != -1 && addedVals < rindex, "details=" + details);
        
        addedVals = details.indexOf("slurp", rindex);
        Assert.assertTrue(addedVals > rindex, "details=" + details);
        addedVals = details.indexOf("potatoes", rindex);
        Assert.assertTrue(addedVals > rindex, "details=" + details);
    }
    
    /**
     * Test method for {@link com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder#build()}.
     */
    @Test
    public void testBuild() {
        AuditLogMsgBuilder msgBldr = starter("testBuild");
        
        String msg = msgBldr.build();
        Assert.assertTrue(msg.contains("WHAT-api=(testBuild)"), "Test string=" + msg);
    }
    
    @Test
    public void testBuildChangedRemovedAdded() {
        AuditLogMsgBuilder msgBldr = starter("testBuildChangedRemovedAdded");
        String [] origKeys = new String[] { "alpha", "beta", "gamma", "epsilon" };
        String [] origVals = new String[] { "Aval", "Bval", "Gval", "Eval" };
        String [] newKeys  = new String[] { "beta", "gamma", "delta" };
        String [] newVals  = new String[] { "Bval", "Gammaval", "Dval" };
        Struct origFields  = setupEntity(origKeys, origVals);
        Struct newFields   = setupEntity(newKeys, newVals);
        msgBldr.whatDetails("Bsame", origFields, newFields);
        
        String msg = msgBldr.build();
        Assert.assertTrue(msg.contains("WHAT-api=(testBuildChangedRemovedAdded)"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("CHANGED=(gamma=(FROM=(Gval);TO=(Gammaval))"), "Test string=" + msg);
        Assert.assertTrue(msg.contains("ADDED=(delta=\"Dval\")"), "Test string=" + msg);

        // order not important
        boolean removedAlpha   = msg.contains("REMOVED=(alpha=\"Aval\",epsilon=\"Eval\")");
        boolean removedEpsilon = msg.contains("REMOVED=(epsilon=\"Eval\",alpha=\"Aval\")");
        Assert.assertTrue(removedAlpha | removedEpsilon, "Test string=" + msg);

    }

    @Test
    public void testFindChangedValues() {
        String changed = "CHANGED=(org=(FROM=(testOrg);TO=(NewOrg));description=(FROM=(Test Domain1);TO=(Test2 Domain)););";
        DefaultAuditLogMsgBuilder msgBldr = new DefaultAuditLogMsgBuilder();

        // get value without prefix
        Array noPrefixValues = new Array();
        msgBldr.findChangedValues(noPrefixValues, changed, "FROM=(", "));", false);
        Assert.assertTrue(noPrefixValues.size() == 2, "values size=" + noPrefixValues.size());
        String fromToVal1 = "org=(FROM=(testOrg);TO=(NewOrg";
        String fromToVal2 = "description=(FROM=(Test Domain1);TO=(Test2 Domain";
        String noPrefFromToVal1 = "FROM=(testOrg);TO=(NewOrg";
        String noPrefFromToVal2 = "FROM=(Test Domain1);TO=(Test2 Domain";
        for (int cnt = 0; cnt < noPrefixValues.size(); ++cnt) {
            String fromToVal = (String) noPrefixValues.get(cnt);
            Assert.assertFalse(fromToVal.contains(fromToVal1) || fromToVal.contains(fromToVal2), "From/To=" + fromToVal);
            Assert.assertTrue(fromToVal.contains(noPrefFromToVal1) || fromToVal.contains(noPrefFromToVal2), "From/To=" + fromToVal);
        }

        // get value with prefix
        Array prefixValues = new Array();
        msgBldr.findChangedValues(prefixValues, changed, "FROM=(", "));", true);
        Assert.assertTrue(prefixValues.size() == 2, "values size=" + prefixValues.size());
        for (int cnt = 0; cnt < prefixValues.size(); ++cnt) {
            String fromToVal = (String) prefixValues.get(cnt);
            Assert.assertTrue(fromToVal.contains(fromToVal1) || fromToVal.contains(fromToVal2), "From/To=" + fromToVal);
        }
    }

    @Test
    public void testGetMatchedGroup() {
        String  GEN_FLD_PAT = "=\\(([^\\)]+)\\);.*";
        Pattern PAT_VERS = Pattern.compile(".*(VERS)" + GEN_FLD_PAT);

        String logMsg = "VERS=(test-0.1);WHEN=(2015-03-26T20:30:34.457Z);WHO=(who-name=testadminuser,who-domain=" + USER_DOMAIN
                + ",who-fullname=" + USER_DOMAIN + ".testadminuser);WHY=(zmsjcltest);WHERE=(server-ip=somehost.somecompany.com,server-https-port=0,server-http-port=10080);CLIENT-IP=(127.0.0.1);WHAT-method=(PUT);WHAT-api=(putdomainmeta);WHAT-domain=(MetaDom1);WHAT-entity=(meta);WHAT-details=(meta-attrs=(CHANGED=(org=(FROM=(testOrg);TO=(NewOrg));description=(FROM=(Test Domain1);TO=(Test2 Domain)););REMOVED=(null);ADDED=(auditEnabled=true);));";
        CharSequence charSeq = logMsg.subSequence(0, logMsg.length());
        DefaultAuditLogMsgBuilder msgBldr = new DefaultAuditLogMsgBuilder();
        String group = msgBldr.getMatchedGroup(PAT_VERS, 2, charSeq);
        Assert.assertNotNull(group);
        Assert.assertEquals(group, "test-0.1");

        // choose bad group number
        group = msgBldr.getMatchedGroup(PAT_VERS, 3, charSeq);
        Assert.assertNull(group);

        // choose group number 0 - whole string
        group = msgBldr.getMatchedGroup(PAT_VERS, 0, charSeq);
        Assert.assertNotNull(group);
        Assert.assertEquals(group, logMsg);
    }

    @Test
    public void testParse() {
        String logMsg = "WHEN=(2015-03-26T20:30:34.457Z);WHO=(who-name=testadminuser,who-domain=" + USER_DOMAIN
                + ",who-fullname=" + USER_DOMAIN + ".testadminuser);WHY=(zmsjcltest);WHERE=(server-ip=somehost.somecompany.com,server-https-port=0,server-http-port=10080);CLIENT-IP=(127.0.0.1);WHAT-method=(PUT);WHAT-api=(putdomainmeta);WHAT-domain=(MetaDom1);WHAT-entity=(meta);WHAT-details=(meta-attrs=(CHANGED=(metattrs=(ADDED-VALUES=(\"" + USER_DOMAIN + ".doe\"));metattrs=(REMOVED-VALUES=(\"" + USER_DOMAIN + ".dough\"));org=(FROM=(testOrg);TO=(NewOrg));description=(FROM=(Test Domain1);TO=(Test2 Domain)););REMOVED=(null);ADDED=(auditEnabled=true);));";
        AuditLogMsgBuilder msgBldr = new DefaultAuditLogMsgBuilder();
        Struct parsed = msgBldr.parse(logMsg);
        Assert.assertNotNull(parsed);
        Assert.assertTrue(parsed.containsKey("WHEN"));
        String val = parsed.getString("WHEN");
        Assert.assertTrue(val.contains("2015-03-26T20:30:34.457Z"));
        Assert.assertTrue(parsed.containsKey("WHO"));
        val = parsed.getString("WHO");
        Assert.assertTrue(val.contains("who-name=testadminuser,who-domain=" + USER_DOMAIN + ",who-fullname=" + USER_DOMAIN + ".testadminuser"));
        Assert.assertTrue(parsed.containsKey("WHY"));
        val = parsed.getString("WHY");
        Assert.assertTrue(val.contains("zmsjcltest"));
        Assert.assertTrue(parsed.containsKey("WHERE"));
        val = parsed.getString("WHERE");
        Assert.assertTrue(val.contains("server-ip=somehost.somecompany.com,server-https-port=0,server-http-port=10080"));
        Assert.assertTrue(parsed.containsKey("CLIENT-IP"));
        val = parsed.getString("CLIENT-IP");
        Assert.assertTrue(val.contains("127.0.0.1"));
        Assert.assertTrue(parsed.containsKey("WHAT-method"));
        val = parsed.getString("WHAT-method");
        Assert.assertTrue(val.contains("PUT"));
        Assert.assertTrue(parsed.containsKey("WHAT-api"));
        val = parsed.getString("WHAT-api");
        Assert.assertTrue(val.contains("putdomainmeta"));
        Assert.assertTrue(parsed.containsKey("WHAT-domain"));
        val = parsed.getString("WHAT-domain");
        Assert.assertTrue(val.contains("MetaDom1"));
        Assert.assertTrue(parsed.containsKey("WHAT-entity"));
        val = parsed.getString("WHAT-entity");
        Assert.assertTrue(val.contains("meta"));

        Assert.assertTrue(parsed.containsKey("WHAT-details"));
        Struct details = parsed.getStruct("WHAT-details");
        Assert.assertNotNull(details);
        Assert.assertTrue(details.containsKey("CHANGED"));
        val  = details.getString("CHANGED");
        Assert.assertTrue(val.contains("CHANGED=(metattrs=(ADDED-VALUES=(\"" + USER_DOMAIN + ".doe\"));metattrs=(REMOVED-VALUES=(\"" + USER_DOMAIN + ".dough\"));org=(FROM=(testOrg);TO=(NewOrg))"), val);

        Assert.assertTrue(details.containsKey("REMOVED"));
        val = details.getString("REMOVED");
        Assert.assertTrue(val.contains("null"));
        Assert.assertTrue(details.containsKey("ADDED"));
        val = details.getString("ADDED");
        Assert.assertTrue(val.contains("auditEnabled=true"));

        Assert.assertTrue(details.containsKey("ADDED-VALUES"));
        Array values = (Array) details.get("ADDED-VALUES");
        Assert.assertNotNull(values);
        Assert.assertTrue(values.size() == 1, "values size=" + values.size());
        for (int cnt = 0; cnt < values.size(); ++cnt) {
            String addedVal = (String) values.get(cnt);
            Assert.assertTrue(addedVal.contains("" + USER_DOMAIN + ".doe"));
        }

        Assert.assertTrue(details.containsKey("REMOVED-VALUES"));
        values = (Array) details.get("REMOVED-VALUES");
        Assert.assertNotNull(values);
        Assert.assertTrue(values.size() == 1, "values size=" + values.size());
        for (int cnt = 0; cnt < values.size(); ++cnt) {
            String removedVal = (String) values.get(cnt);
            Assert.assertTrue(removedVal.contains("" + USER_DOMAIN + ".dough"));
        }

        Assert.assertTrue(details.containsKey("FROM-TO-VALUES"));
        values = (Array) details.get("FROM-TO-VALUES");
        Assert.assertNotNull(values);
        Assert.assertTrue(values.size() == 2, "values size=" + values.size());
        String fromToVal1 = "org=(FROM=(testOrg);TO=(NewOrg";
        String fromToVal2 = "description=(FROM=(Test Domain1);TO=(Test2 Domain";
        for (int cnt = 0; cnt < values.size(); ++cnt) {
            String fromToVal = (String) values.get(cnt);
            Assert.assertTrue(fromToVal.contains(fromToVal1) || fromToVal.contains(fromToVal2), "From/To=" + fromToVal);
        }
    }
 
    @Test
    public void testParseChangesAddedRemovedValues() {
        String logMsg = "VERS=(athenz-def-1.0);WHEN=(2015-04-02T17:09:31.387Z);WHO=(v=U1;d=user;n=jdoe);WHY=(audittest);WHERE=(server-ip=localhost,server-https-port=0,server-http-port=10080);CLIENT-IP=(MOCKCLIENT_HOST_NAME);WHAT-method=(PUT);WHAT-api=(putpolicy);WHAT-domain=(CrossDomainAccessDom1);WHAT-entity=(tenancy.coretech.storage.writer);WHAT-details=(policy-attrs=(CHANGED=(modified=(FROM=(2015-04-02T17:09:31.354Z);TO=(2015-04-02T17:09:31.387Z));assertions=(ADDED-VALUES=({role: \"CrossDomainAccessDom1:role.writer\", action: \"ASSUME_ROLE\", effect: \"ALLOW\", resource: \"coretech:role.storage.tenant.CrossDomainAccessDom1.writer\"}));assertions=(REMOVED-VALUES=({role: \"CrossDomainAccessDom1:role.admin\", action: \"ASSUME_ROLE\", resource: \"coretech:role.storage.tenant.CrossDomainAccessDom1.writer\"})););REMOVED=(null);ADDED=(null);));";

        AuditLogMsgBuilder msgBldr = new DefaultAuditLogMsgBuilder();
        Struct parsed = msgBldr.parse(logMsg);
        Assert.assertNotNull(parsed);
        Assert.assertTrue(parsed.containsKey("WHEN"));
        String val = parsed.getString("WHEN");
        Assert.assertTrue(val.contains("2015-04-02T17:09:31.387Z"));

        Assert.assertTrue(parsed.containsKey("WHAT-details"));
        Struct details = parsed.getStruct("WHAT-details");
        Assert.assertNotNull(details);
        Assert.assertTrue(details.containsKey("CHANGED"));
        val  = details.getString("CHANGED");
        Assert.assertTrue(val.contains("CHANGED=(modified=(FROM=(2015-04-02T17:09:31.354Z);"), val);

        Assert.assertTrue(details.containsKey("REMOVED-VALUES"));
        Array values = (Array) details.get("REMOVED-VALUES");
        Assert.assertNotNull(values);
        Assert.assertTrue(values.size() == 1, "values size=" + values.size());
        for (int cnt = 0; cnt < values.size(); ++cnt) {
            String removedVal = (String) values.get(cnt);
            Assert.assertTrue(removedVal.contains("assertions=(REMOVED-VALUES=({role: \"CrossDomainAccessDom1:role.admin\", action: \"ASSUME_ROLE\", resource: \"coretech:role.storage.tenant.CrossDomainAccessDom1.writer\"})"), val);
        }

        Assert.assertTrue(details.containsKey("ADDED-VALUES"));
        values = (Array) details.get("ADDED-VALUES");
        Assert.assertNotNull(values);
        Assert.assertTrue(values.size() == 1, "values size=" + values.size());
        for (int cnt = 0; cnt < values.size(); ++cnt) {
            String addedVal = (String) values.get(cnt);
            Assert.assertTrue(addedVal.contains("assertions=(ADDED-VALUES=({role: \"CrossDomainAccessDom1:role.writer\", action: \"ASSUME_ROLE\", effect: \"ALLOW\", resource: \"coretech:role.storage.tenant.CrossDomainAccessDom1.writer\"})"), val);
        }
    }

    @Test
    public void testParseChangesAddedRemovedEmbedded() {
        String logMsg = "VERS=(athenz-def-1.0);WHEN=(2015-04-02T18:30:58.451Z);WHO=(v=U1;d=user;n=jdoe);WHY=(audittest);WHERE=(server-ip=localhost,server-https-port=0,server-http-port=10080);CLIENT-IP=(MOCKCLIENT_HOST_NAME);WHAT-method=(PUT);WHAT-api=(puttenantroles);WHAT-domain=(coretech);WHAT-entity=(storage:AddTenancyDom1);WHAT-details=(AddTenancyDom1=(CHANGED=(role=(CHANGED=(null);role=(REMOVED=(null));role=(ADDED=(storage.tenant.AddTenancyDom1.reader={trust: \"AddTenancyDom1\", modified: \"2015-04-02T18:30:58.451Z\", name: \"coretech:role.storage.tenant.AddTenancyDom1.reader\"},storage.tenant.AddTenancyDom1.admin={trust: \"AddTenancyDom1\", modified: \"2015-04-02T18:30:58.451Z\", name: \"coretech:role.storage.tenant.AddTenancyDom1.admin\"},storage.tenant.AddTenancyDom1.writer={trust: \"AddTenancyDom1\", modified: \"2015-04-02T18:30:58.451Z\", name: \"coretech:role.storage.tenant.AddTenancyDom1.writer\"}));policy=(CHANGED=(null);policy=(REMOVED=(null));policy=(ADDED=(storage.tenant.AddTenancyDom1.reader={assertions: [{role: \"coretech:role.storage.tenant.AddTenancyDom1.reader\", action: \"READ\", resource: \"coretech:service.storage.tenant.AddTenancyDom1.*\"}], modified: \"2015-04-02T18:30:58.451Z\", name: \"coretech:policy.storage.tenant.AddTenancyDom1.reader\"},storage.tenant.AddTenancyDom1.admin={assertions: [{role: \"coretech:role.storage.tenant.AddTenancyDom1.admin\", action: \"*\", resource: \"coretech:service.storage.tenant.AddTenancyDom1.*\"}], modified: \"2015-04-02T18:30:58.451Z\", name: \"coretech:policy.storage.tenant.AddTenancyDom1.admin\"},storage.tenant.AddTenancyDom1.writer={assertions: [{role: \"coretech:role.storage.tenant.AddTenancyDom1.writer\", action: \"WRITE\", resource: \"coretech:service.storage.tenant.AddTenancyDom1.*\"}], modified: \"2015-04-02T18:30:58.451Z\", name: \"coretech:policy.storage.tenant.AddTenancyDom1.writer\"})););AddTenancyDom1=(REMOVED=(null));AddTenancyDom1=(ADDED=(null)););";

        AuditLogMsgBuilder msgBldr = new DefaultAuditLogMsgBuilder();
        Struct parsed = msgBldr.parse(logMsg);
        Assert.assertNotNull(parsed);
        Assert.assertTrue(parsed.containsKey("WHO"));
        String val = parsed.getString("WHO");
        Assert.assertTrue(val.contains("v=U1;d=user;n=jdoe"));

        Assert.assertTrue(parsed.containsKey("WHAT-details"));
        Struct details = parsed.getStruct("WHAT-details");
        Assert.assertNotNull(details);

        Assert.assertTrue(details.containsKey("REMOVED"));
        val = details.getString("REMOVED");
        Assert.assertTrue(val.contains("null"));
        Assert.assertTrue(details.containsKey("ADDED"));
        val = details.getString("ADDED");
        Assert.assertTrue(val.contains("null"));

        Assert.assertTrue(details.containsKey("CHANGED"));
        val  = details.getString("CHANGED");
        Assert.assertTrue(val.contains("CHANGED=(role=(CHANGED=(null);"), val);

        // get all the embedded ADDED/REMOVED from changes
        Assert.assertTrue(details.containsKey("EMBEDDED-REMOVED"));
        Array values = (Array) details.get("EMBEDDED-REMOVED");
        Assert.assertNotNull(values);
        Assert.assertTrue(values.size() == 2, "values size=" + values.size());
        String removedEmbeddedVal1 = "role=(REMOVED=(null)";
        String removedEmbeddedVal2 = "policy=(REMOVED=(null)";
        for (int cnt = 0; cnt < values.size(); ++cnt) {
            String removedVal = (String) values.get(cnt);
            boolean matched = removedVal.contains(removedEmbeddedVal1) || removedVal.contains(removedEmbeddedVal2);
            Assert.assertTrue(matched, removedVal);
        }

        Assert.assertTrue(details.containsKey("EMBEDDED-ADDED"));
        values = (Array) details.get("EMBEDDED-ADDED");
        Assert.assertNotNull(values);
        Assert.assertTrue(values.size() == 2, "values size=" + values.size());
        String addedEmbeddedVal1 = "role=(ADDED=(storage.tenant.AddTenancyDom1.reader={trust: \"AddTenancyDom1\",";
        String addedEmbeddedVal2 = "policy=(ADDED=(storage.tenant.AddTenancyDom1.reader={assertions: [{role: \"coretech:role.storage.tenant.AddTenancyDom1.reader\", action: \"READ\",";
        for (int cnt = 0; cnt < values.size(); ++cnt) {
            String addedVal = (String) values.get(cnt);
            boolean matched = addedVal.contains(addedEmbeddedVal1) || addedVal.contains(addedEmbeddedVal2);
            Assert.assertTrue(matched, addedVal);
        }

    }
}
