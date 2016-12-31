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

package com.yahoo.athenz.zts;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import junit.framework.Assert;

public class DomainMetricTest {

    @Test
    public void testsetgetMetricType() {
        DomainMetric dm = new DomainMetric();

        dm.setMetricType(DomainMetricType.ACCESS_ALLOWED);
        dm.setMetricVal(1);

        Assert.assertEquals(DomainMetricType.ACCESS_ALLOWED, dm.getMetricType());
        Assert.assertEquals(1, dm.getMetricVal());
        Assert.assertEquals(DomainMetricType.ACCESS_ALLOWED, DomainMetricType.fromString("ACCESS_ALLOWED"));
    }

    @Test(expectedExceptions = { java.lang.IllegalArgumentException.class })
    public void testMetricTypeException() throws Exception {
        DomainMetricType.fromString("NOT_EXIST");
    }

    @Test
    public void testMetricTypeEqualsTrueFalse() {
        DomainMetric dm1 = new DomainMetric();
        DomainMetric dm2 = new DomainMetric();

        dm1.setMetricType(DomainMetricType.ACCESS_ALLOWED);
        dm1.setMetricVal(1);
        dm2.setMetricType(DomainMetricType.ACCESS_ALLOWED);
        dm2.setMetricVal(1);

        Assert.assertTrue(dm1.equals(dm2));

        // change value
        dm2.setMetricVal(0);
        Assert.assertFalse(dm1.equals(dm2));

        // change type
        dm1.setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY);
        Assert.assertFalse(dm1.equals(dm2));

        Assert.assertFalse(dm1.equals(new String()));
    }

    @Test
    public void testDomainMetrics() {
        DomainMetrics dms1 = new DomainMetrics();
        DomainMetrics dms2 = new DomainMetrics();

        DomainMetric dm = new DomainMetric();

        // set/get test
        List<DomainMetric> dmlist = new ArrayList<DomainMetric>();
        dmlist.add(dm);

        dms1.setDomainName("test.org");
        dms1.setMetricList(dmlist);
        dms2.setDomainName("test.org");
        dms2.setMetricList(dmlist);

        assertEquals("test.org", dms1.getDomainName());
        assertEquals(dmlist, dms1.getMetricList());

        //// equals
        // true case
        Assert.assertTrue(dms1.equals(dms1));
        assertTrue(dms1.equals(dms2));

        // false case
        dms2.setMetricList(new ArrayList<DomainMetric>());
        Assert.assertFalse(dms1.equals(dms2));

        dms2.setDomainName("test.net");
        assertFalse(dms1.equals(dms2));

        assertFalse(dms1.equals(new String()));
    }

}
