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
package com.yahoo.athenz.zms.config;

import static org.testng.Assert.*;

import org.testng.annotations.*;

import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;

public class AllowedOperationTest {

    @BeforeClass(alwaysRun=true)
    public void setUp() throws Exception {
    }

    @AfterClass(alwaysRun=true)
    public void shutdown() {
    }

    @Test
    public void testSetName() {
        String name = "AllowedOperationName";
        AllowedOperation op = new AllowedOperation();
        op.setName(name);
        String gottenName = op.getName();
        assertEquals(gottenName, name);
    }

    @SuppressWarnings("serial")
    @Test
    public void testSetItems() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<String, Set<String>>() {
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
        boolean ret = op.isOperationAllowedOn("opItemType", "opItemValue");
        assertTrue(ret);
    }

    @Test
    public void testIsOperationAllowedOnItemsIsEmpty() {
        AllowedOperation op = new AllowedOperation();
        Map<String, Set<String>> items = new HashMap<String, Set<String>>();
        op.setItems(items);
        boolean ret = op.isOperationAllowedOn("opItemType", "opItemValue");
        assertTrue(ret);
    }

    @SuppressWarnings("serial")
    @Test
    public void testIsOperationAllowedOnOpItemTypeIsNull() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<String, Set<String>>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        boolean ret = op.isOperationAllowedOn(null, "opItemValue");
        assertFalse(ret);
    }

    @SuppressWarnings("serial")
    @Test
    public void testIsOperationAllowedOnOpItemValueIsNull() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<String, Set<String>>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        boolean ret = op.isOperationAllowedOn("opItemType", null);
        assertFalse(ret);
    }

    @SuppressWarnings("serial")
    @Test
    public void testIsOperationAllowedOnOpItemTypeIsNotDefined() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<String, Set<String>>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        boolean ret = op.isOperationAllowedOn("opItemType", "opItemValue");
        assertFalse(ret);
    }

    @SuppressWarnings("serial")
    @Test
    public void testIsOperationAllowedOnOpItemValueIsNotAllowed() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<String, Set<String>>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        boolean ret = op.isOperationAllowedOn("key", "opItemValue");
        assertFalse(ret);
    }

    @SuppressWarnings("serial")
    @Test
    public void testIsOperationAllowedOnOpItemValueIsAllowed() {
        AllowedOperation op = new AllowedOperation();
        Set<String> item = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items = new HashMap<String, Set<String>>() {
            {
                put("key", item);
            }
        };
        op.setItems(items);
        boolean ret = op.isOperationAllowedOn("key", "hoge");
        assertTrue(ret);
    }

    @Test
    public void testEqualsSameObject() {
        AllowedOperation op1 = new AllowedOperation();
        boolean ret = op1.equals(op1);
        assertTrue(ret);
    }

    @Test
    public void testEqualsObjctIsNull() {
        AllowedOperation op1 = new AllowedOperation();
        Object obj = null;
        boolean ret = op1.equals(obj);
        assertFalse(ret);
    }

    @Test
    public void testEqualsDifferentClass() {
        AllowedOperation op1 = new AllowedOperation();
        String str = "fuga";
        boolean ret = op1.equals(str);
        assertFalse(ret);
    }

    @Test
    public void testEqualsNameIsNull() {
        AllowedOperation op1 = new AllowedOperation();
        AllowedOperation op2 = new AllowedOperation();
        op2.setName("AllowedOperation2");

        boolean ret = op1.equals(op2);
        assertFalse(ret);
    }

    @Test
    public void testEqualsBothNameIsNull() {
        AllowedOperation op1 = new AllowedOperation();
        AllowedOperation op2 = new AllowedOperation();

        boolean ret = op1.equals(op2);
        assertTrue(ret);
    }

    @Test
    public void testEqualsSameName() {
        AllowedOperation op1 = new AllowedOperation();
        op1.setName("AllowedOperation1");
        AllowedOperation op2 = new AllowedOperation();
        op2.setName("AllowedOperation1");
        boolean ret = op1.equals(op2);
        assertTrue(ret);
    }

    @Test
    public void testEqualsDifferentName() {
        AllowedOperation op1 = new AllowedOperation();
        op1.setName("AllowedOperation1");
        AllowedOperation op2 = new AllowedOperation();
        op2.setName("AllowedOperation2");
        boolean ret = op1.equals(op2);
        assertFalse(ret);
    }

    @SuppressWarnings("serial")
    @Test
    public void testEqualsSameHashCode() {
        AllowedOperation op1 = new AllowedOperation();
        Set<String> item1 = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items1 = new HashMap<String, Set<String>>() {
            {
                put("key", item1);
            }
        };
        op1.setItems(items1);

        AllowedOperation op2 = new AllowedOperation();
        Set<String> item2 = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items2 = new HashMap<String, Set<String>>() {
            {
                put("key", item2);
            }
        };
        op2.setItems(items2);

        assertEquals(op1.hashCode(), op2.hashCode());
    }

    @SuppressWarnings("serial")
    @Test
    public void testEqualsDifferentHashCode() {
        AllowedOperation op1 = new AllowedOperation();
        Set<String> item1 = new HashSet<String>() {
            {
                add("hoge");
            }
        };
        Map<String, Set<String>> items1 = new HashMap<String, Set<String>>() {
            {
                put("key", item1);
            }
        };
        op1.setItems(items1);

        AllowedOperation op2 = new AllowedOperation();
        Set<String> item2 = new HashSet<String>() {
            {
                add("fuga");
            }
        };
        Map<String, Set<String>> items2 = new HashMap<String, Set<String>>() {
            {
                put("key", item2);
            }
        };
        op2.setItems(items2);

        assertNotEquals(op1.hashCode(), op2.hashCode());
    }
}
