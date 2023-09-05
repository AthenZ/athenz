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
package com.yahoo.athenz.zms.config;

import static org.testng.Assert.*;

import org.testng.annotations.*;

import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;

public class AllowedOperationTest {

    @Test
    public void testSetName() {
        String name = "AllowedOperationName";
        AllowedOperation op = new AllowedOperation();
        op.setName(name);
        String gottenName = op.getName();
        assertEquals(gottenName, name);
    }

    @Test
    public void testSetItems() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);

        Map<String, Set<String>> gottenItems = op.getItems();
        assertEquals(gottenItems, items);
    }


    @Test
    public void testIsOperationAllowedOnNoItems() {
        AllowedOperation op = new AllowedOperation();
        assertTrue(op.isOperationAllowedOn("opItemType", "opItemValue", AllowedOperation.MatchType.EQUALS));
    }

    @Test
    public void testIsOperationAllowedOnItemsIsEmpty() {
        AllowedOperation op = new AllowedOperation();
        Map<String, Set<String>> items = new HashMap<>();
        op.setItems(items);
        assertTrue(op.isOperationAllowedOn("opItemType", "opItemValue", AllowedOperation.MatchType.EQUALS));
    }

    @Test
    public void testIsOperationAllowedOnOpItemTypeIsNull() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        assertFalse(op.isOperationAllowedOn(null, "opItemValue", AllowedOperation.MatchType.EQUALS));
    }

    @Test
    public void testIsOperationAllowedOnOpItemValueIsNull() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        assertFalse(op.isOperationAllowedOn("opItemType", null, AllowedOperation.MatchType.EQUALS));
    }

    @Test
    public void testIsOperationAllowedOnOpItemTypeIsNotDefined() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        assertFalse(op.isOperationAllowedOn("opItemType", "opItemValue", AllowedOperation.MatchType.EQUALS));
    }

    @Test
    public void testIsOperationAllowedOnOpItemValueIsNotAllowed() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        assertFalse(op.isOperationAllowedOn("key", "opItemValue", AllowedOperation.MatchType.EQUALS));
    }

    @Test
    public void testIsOperationAllowedOnOpItemValueIsAllowed() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        assertTrue(op.isOperationAllowedOn("key", "hoge", AllowedOperation.MatchType.EQUALS));
    }

    @Test
    public void testEqualsSameObject() {
        AllowedOperation op1 = new AllowedOperation();
        //noinspection SimplifiedTestNGAssertion,EqualsWithItself
        assertTrue(op1.equals(op1));
    }

    @Test
    public void testEqualsObjctIsNull() {
        AllowedOperation op1 = new AllowedOperation();
        //noinspection SimplifiedTestNGAssertion,ObjectEqualsNull,ConstantConditions
        assertFalse(op1.equals(null));
    }

    @Test
    public void testEqualsDifferentClass() {
        AllowedOperation op1 = new AllowedOperation();
        //noinspection SimplifiedTestNGAssertion,EqualsBetweenInconvertibleTypes
        assertFalse(op1.equals("fail"));
    }

    @Test
    public void testEqualsNameIsNull() {
        AllowedOperation op1 = new AllowedOperation();
        AllowedOperation op2 = new AllowedOperation();
        op2.setName("AllowedOperation2");

        assertFalse(op1.equals(op2));
    }

    @Test
    public void testEqualsBothNameIsNull() {
        AllowedOperation op1 = new AllowedOperation();
        AllowedOperation op2 = new AllowedOperation();

        assertTrue(op1.equals(op2));
    }

    @Test
    public void testEqualsSameName() {
        AllowedOperation op1 = new AllowedOperation();
        op1.setName("AllowedOperation1");
        AllowedOperation op2 = new AllowedOperation();
        op2.setName("AllowedOperation1");
        assertTrue(op1.equals(op2));
    }

    @Test
    public void testEqualsDifferentName() {
        AllowedOperation op1 = new AllowedOperation();
        op1.setName("AllowedOperation1");
        AllowedOperation op2 = new AllowedOperation();
        op2.setName("AllowedOperation2");
        assertFalse(op1.equals(op2));
    }

    @Test
    public void testEqualsSameHashCode() {
        AllowedOperation op1 = new AllowedOperation();
        Set<String> item1 = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items1 = new HashMap<>() {
            {
                put("key", item1);
            }
        };
        op1.setItems(items1);

        AllowedOperation op2 = new AllowedOperation();
        Set<String> item2 = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items2 = new HashMap<>() {
            {
                put("key", item2);
            }
        };
        op2.setItems(items2);

        assertEquals(op1.hashCode(), op2.hashCode());
    }

    @Test
    public void testEqualsDifferentHashCode() {
        AllowedOperation op1 = new AllowedOperation();
        Set<String> item1 = new HashSet<>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items1 = new HashMap<>() {
            {
                put("key", item1);
            }
        };
        op1.setItems(items1);

        AllowedOperation op2 = new AllowedOperation();
        Set<String> item2 = new HashSet<>() {
            {
                add("fuga");
            }
        };
        Map<String, Set<String>> items2 = new HashMap<>() {
            {
                put("key", item2);
            }
        };
        op2.setItems(items2);

        assertNotEquals(op1.hashCode(), op2.hashCode());
    }

    @Test
    public void testIsOperationAllowedStartsWith() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<>() {
            {
                add("config.reader.");
                add("config.writer.");
            }
        };
        Map<String, Set<String>> items = new HashMap<>() {
            {
                put("cfg", item);
            }
        };
        op.setItems(items);

        assertTrue(op.isOperationAllowedOn("cfg", "config.reader.role1", AllowedOperation.MatchType.STARTS_WITH));
        assertTrue(op.isOperationAllowedOn("cfg", "config.writer.role1", AllowedOperation.MatchType.STARTS_WITH));
        assertTrue(op.isOperationAllowedOn("cfg", "config.reader.", AllowedOperation.MatchType.STARTS_WITH));
        assertTrue(op.isOperationAllowedOn("cfg", "config.reader.role1", AllowedOperation.MatchType.STARTS_WITH));
        assertFalse(op.isOperationAllowedOn("cfg", "config.readers.role1", AllowedOperation.MatchType.STARTS_WITH));
        assertFalse(op.isOperationAllowedOn("cfg", "config.writers.role1", AllowedOperation.MatchType.STARTS_WITH));
        assertFalse(op.isOperationAllowedOn("cfg", "config.reader.role1", AllowedOperation.MatchType.EQUALS));
    }
}
