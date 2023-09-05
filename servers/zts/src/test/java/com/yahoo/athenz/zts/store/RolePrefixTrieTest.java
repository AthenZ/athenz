/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zts.store;

import org.testng.annotations.Test;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.testng.Assert.assertEquals;

public class RolePrefixTrieTest {

    /*
        \--top1
        |   |
        |   |--sub1 (role1)
        |   |   |
        |   |   |--sub2 (role2, role3)
        |   |   |   |
        |   |   |   |--service* (role4)
        |   |   |
        |   |   |--sub3 (role5)
        |   |   |
        |   |   |--sub3* (role6)
        |   |
        |   |--sub2 (role2)
        |
        |--top2 (role1)
             |
             |--sub2 (role8)
             |
             |--sub1 (role3)
                  |
                  |--service* (role2, role5)
     */
    private RolePrefixTrie generateTestTrie() {
        RolePrefixTrie rolePrefixTrie = new RolePrefixTrie();
        rolePrefixTrie.insert("top1.sub1.*", "role1");
        rolePrefixTrie.insert("top1.sub1.sub2.*", "role2");
        rolePrefixTrie.insert("top1.sub1.sub2.*", "role3");
        rolePrefixTrie.insert("top1.sub1.sub2.service*", "role4");

        rolePrefixTrie.insert("top1.sub1.sub3.*", "role5");
        rolePrefixTrie.insert("top1.sub1.sub3*", "role6");
        rolePrefixTrie.insert("top1.sub2.*", "role2");

        rolePrefixTrie.insert("top2.*", "role1");
        rolePrefixTrie.insert("top2.sub2.*", "role8");
        rolePrefixTrie.insert("top2.sub1.*", "role3");
        rolePrefixTrie.insert("top2.sub1.service*", "role2");
        rolePrefixTrie.insert("top2.sub1.service*", "role5");

        return rolePrefixTrie;
    }

    private static class insertJob implements Runnable {
        private final String prefix;
        private final String role;
        private final RolePrefixTrie rolePrefixTrie;
        public insertJob(RolePrefixTrie rolePrefixTrie, String prefix, String role) {
            this.rolePrefixTrie = rolePrefixTrie;
            this.prefix = prefix;
            this.role = role;
        }

        @Override
        public void run() {
            rolePrefixTrie.insert(prefix, role);
        }
    }

    private static class findAndAssertJob implements Runnable {
        private final String principal;
        private final RolePrefixTrie rolePrefixTrie;
        private final String[] roles;
        public findAndAssertJob(RolePrefixTrie rolePrefixTrie, String principal, String... roles) {
            this.rolePrefixTrie = rolePrefixTrie;
            this.principal = principal;
            this.roles = roles;
        }

        @Override
        public void run() {
            Set<String> rolesReturned = rolePrefixTrie.findMatchingValues(principal);
            assertEquals(rolesReturned.size(), roles.length);
            assertThat(rolesReturned, containsInAnyOrder(roles));
        }
    }

    private RolePrefixTrie generateTestTrieAsync() {
        RolePrefixTrie rolePrefixTrie = new RolePrefixTrie();
        ExecutorService es = Executors.newFixedThreadPool(30);
        es.execute(new insertJob(rolePrefixTrie, "top1.sub1.*", "role1"));

        es.execute(new insertJob(rolePrefixTrie, "top1.sub1.*", "role1"));
        es.execute(new insertJob(rolePrefixTrie, "top1.sub1.sub2.*", "role2"));
        es.execute(new insertJob(rolePrefixTrie, "top1.sub1.sub2.*", "role3"));
        es.execute(new insertJob(rolePrefixTrie, "top1.sub1.sub2.service*", "role4"));

        es.execute(new insertJob(rolePrefixTrie, "top1.sub1.sub3.*", "role5"));
        es.execute(new insertJob(rolePrefixTrie, "top1.sub1.sub3*", "role6"));
        es.execute(new insertJob(rolePrefixTrie, "top1.sub2.*", "role2"));

        es.execute(new insertJob(rolePrefixTrie, "top2.*", "role1"));
        es.execute(new insertJob(rolePrefixTrie, "top2.sub2.*", "role8"));
        es.execute(new insertJob(rolePrefixTrie, "top2.sub1.*", "role3"));
        es.execute(new insertJob(rolePrefixTrie, "top2.sub1.service*", "role2"));
        es.execute(new insertJob(rolePrefixTrie, "top2.sub1.service*", "role5"));

        try {
            es.shutdown();
            es.awaitTermination(1, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {
        }
        return rolePrefixTrie;
    }

    @Test
    public void testRolePrefixTrieFind() {
        RolePrefixTrie rolePrefixTrie = generateTestTrie();
        Set<String> roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub2.servicetest");
        assertEquals(roles.size(), 4);
        assertThat(roles, containsInAnyOrder("role1", "role2", "role3", "role4"));

        roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub2.serviceother");
        assertEquals(roles.size(), 4);
        assertThat(roles, containsInAnyOrder("role1", "role2", "role3", "role4"));

        roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub2.sernotenough");
        assertEquals(roles.size(), 3);
        assertThat(roles, containsInAnyOrder("role1", "role2", "role3"));

        roles = rolePrefixTrie.findMatchingValues("top1.sub1.test");
        assertEquals(roles.size(), 1);
        assertThat(roles, containsInAnyOrder("role1"));

        roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub3.test");
        assertEquals(roles.size(), 2);
        assertThat(roles, containsInAnyOrder("role1", "role5"));

        roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub3test");
        assertEquals(roles.size(), 2);
        assertThat(roles, containsInAnyOrder("role1", "role6"));

        roles = rolePrefixTrie.findMatchingValues("top1.test");
        assertEquals(roles.size(), 0);

        roles = rolePrefixTrie.findMatchingValues("top2.sub2.test");
        assertEquals(roles.size(), 2);
        assertThat(roles, containsInAnyOrder("role1", "role8"));

        roles = rolePrefixTrie.findMatchingValues("top2.sub1.servicetest");
        assertEquals(roles.size(), 4);
        assertThat(roles, containsInAnyOrder("role1", "role2", "role3", "role5"));

        roles = rolePrefixTrie.findMatchingValues("top2.sub1.other");
        assertEquals(roles.size(), 2);
        assertThat(roles, containsInAnyOrder("role1", "role3"));
    }

    @Test
    public void testRolePrefixTrieInsertAndFindAsync() {
        RolePrefixTrie rolePrefixTrie = generateTestTrieAsync();
        ExecutorService es = Executors.newFixedThreadPool(30);
        es.execute(new findAndAssertJob(rolePrefixTrie, "top1.sub1.sub2.servicetest", "role1", "role2", "role3", "role4"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top1.sub1.sub2.serviceother", "role1", "role2", "role3", "role4"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top1.sub1.sub2.sernotenough", "role1", "role2", "role3"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top1.sub1.test", "role1"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top1.sub1.sub3.test", "role1", "role5"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top1.sub1.sub3test", "role1", "role6"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top1.test"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top2.sub2.test", "role1", "role8"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top2.sub1.servicetest", "role1", "role2", "role3", "role5"));
        es.execute(new findAndAssertJob(rolePrefixTrie, "top2.sub1.other", "role1", "role3"));
        try {
            es.shutdown();
            es.awaitTermination(1, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {
        }
    }

    @Test
    public void testRolePrefixTrieDelete() {
        RolePrefixTrie rolePrefixTrie = generateTestTrie();

        // Run the same deletions twice to verify trying to delete missing prefixes is valid
        for (int i = 0; i < 2; ++i) {
            // Delete a couple of prefixes, verify only relevant principals affected
            rolePrefixTrie.delete("top1.sub1.sub3.*", "role5");
            rolePrefixTrie.delete("top2.sub1.service*", "role2");

            Set<String> roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub2.servicetest");
            assertEquals(roles.size(), 4);
            assertThat(roles, containsInAnyOrder("role1", "role2", "role3", "role4"));

            roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub2.serviceother");
            assertEquals(roles.size(), 4);
            assertThat(roles, containsInAnyOrder("role1", "role2", "role3", "role4"));

            roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub2.sernotenough");
            assertEquals(roles.size(), 3);
            assertThat(roles, containsInAnyOrder("role1", "role2", "role3"));

            roles = rolePrefixTrie.findMatchingValues("top1.sub1.test");
            assertEquals(roles.size(), 1);
            assertThat(roles, containsInAnyOrder("role1"));

            roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub3.test");
            assertEquals(roles.size(), 1);
            assertThat(roles, containsInAnyOrder("role1"));

            roles = rolePrefixTrie.findMatchingValues("top1.sub1.sub3test");
            assertEquals(roles.size(), 2);
            assertThat(roles, containsInAnyOrder("role1", "role6"));

            roles = rolePrefixTrie.findMatchingValues("top1.test");
            assertEquals(roles.size(), 0);

            roles = rolePrefixTrie.findMatchingValues("top2.sub2.test");
            assertEquals(roles.size(), 2);
            assertThat(roles, containsInAnyOrder("role1", "role8"));

            roles = rolePrefixTrie.findMatchingValues("top2.sub1.servicetest");
            assertEquals(roles.size(), 3);
            assertThat(roles, containsInAnyOrder("role1", "role3", "role5"));

            roles = rolePrefixTrie.findMatchingValues("top2.sub1.other");
            assertEquals(roles.size(), 2);
            assertThat(roles, containsInAnyOrder("role1", "role3"));
        }

        // Delete branches from top2 and verify only relevant principals affected
        rolePrefixTrie.delete("top2.*", "role1");
        rolePrefixTrie.delete("top2.sub2.*", "role8");
        rolePrefixTrie.delete("top2.sub1.service*", "role5");

        Set<String> roles = rolePrefixTrie.findMatchingValues("top2.sub2.test");
        assertEquals(roles.size(), 0);

        roles = rolePrefixTrie.findMatchingValues("top2.sub1.servicetest");
        assertEquals(roles.size(), 1);
        assertThat(roles, containsInAnyOrder("role3"));

        roles = rolePrefixTrie.findMatchingValues("top2.sub1.other");
        assertEquals(roles.size(), 1);
        assertThat(roles, containsInAnyOrder("role3"));
    }
}
