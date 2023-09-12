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

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RolePrefixTrie implements PrefixTrie<String> {
    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
    private final Lock readLock = rwLock.readLock();
    private final Lock writeLock = rwLock.writeLock();

    private final TrieNode root = new TrieNode();

    private static class TrieNode {
        private final HashMap<String, TrieNode> children = new HashMap<>();
        private final Set<String> roles = new HashSet<>();
    }

    @Override
    public void insert(String prefix, String value) {
        try {
            writeLock.lock();
            if (prefix.endsWith(".*")) {
                prefix = prefix.substring(0, prefix.length() - 2);
            }
            TrieNode current = root;
            final String[] prefixSections = prefix.split("\\.");
            for (String domain: prefixSections) {
                current = current.children.computeIfAbsent(domain, c -> new TrieNode());
            }
            // Add roles in the last node
            current.roles.add(value);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void delete(String prefix, String value) {
        try {
            writeLock.lock();
            if (prefix.endsWith(".*")) {
                prefix = prefix.substring(0, prefix.length() - 2);
            }
            String[] prefixSections = prefix.split("\\.");
            delete(root, prefixSections, value, 0);
        } finally {
            writeLock.unlock();
        }
    }

    private boolean delete(TrieNode current, String[] prefixSections, String role, int index) {
        if (index == prefixSections.length) {
            current.roles.remove(role);
            return current.roles.isEmpty() && current.children.isEmpty();
        }
        String section = prefixSections[index];
        TrieNode node = current.children.get(section);
        if (node == null) {
            return false;
        }
        boolean shouldDeleteCurrentNode = delete(node, prefixSections, role, index + 1);

        if (shouldDeleteCurrentNode) {
            current.children.remove(section);
            return current.roles.isEmpty() && current.children.isEmpty();
        }
        return false;
    }

    @Override
    public Set<String> findMatchingValues(String text) {
        try {
            readLock.lock();
            Set<String> roles = new HashSet<>();
            TrieNode current = root;
            final String[] principalSections = text.split("\\.");

            for (int i = 0; i < principalSections.length; i++) {
                if (isLastSection(principalSections, i)) {
                    String service = principalSections[i];
                    for (String prefix : current.children.keySet()) {
                        if (prefix.endsWith("*") && service.startsWith(prefix.substring(0, prefix.length() - 1))) {
                            roles.addAll(current.children.get(prefix).roles);
                        }
                    }
                } else {
                    String domain = principalSections[i];
                    TrieNode node = current.children.get(domain);
                    if (node == null) {
                        return roles;
                    }
                    roles.addAll(node.roles);
                    current = node;
                }
            }
            return roles;
        } finally {
            readLock.unlock();
        }
    }


    private boolean isLastSection(String[] principalSections, int i) {
        return i == principalSections.length - 1;
    }
}
