/*
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

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

@SuppressWarnings("EqualsBetweenInconvertibleTypes")
public class DomainMetricTest {

    @Test
    public void testsetgetMetricType() {
        DomainMetric dm = new DomainMetric();

        dm.setMetricType(DomainMetricType.ACCESS_ALLOWED);
        dm.setMetricVal(1);

        assertEquals(DomainMetricType.ACCESS_ALLOWED, dm.getMetricType());
        assertEquals(1, dm.getMetricVal());
        assertEquals(DomainMetricType.ACCESS_ALLOWED, DomainMetricType.fromString("ACCESS_ALLOWED"));
    }

    @Test(expectedExceptions = { java.lang.IllegalArgumentException.class })
    public void testMetricTypeException() {
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

        assertEquals(dm1, dm2);

        // change value
        dm2.setMetricVal(0);
        assertNotEquals(dm1, dm2);

        // change type
        dm1.setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY);
        assertNotEquals(dm1, dm2);

        assertNotEquals("", dm1);
    }

    @SuppressWarnings("EqualsWithItself")
    @Test
    public void testDomainMetrics() {
        DomainMetrics dms1 = new DomainMetrics();
        DomainMetrics dms2 = new DomainMetrics();

        DomainMetric dm = new DomainMetric();

        // set/get test
        List<DomainMetric> dmlist = new ArrayList<>();
        dmlist.add(dm);

        dms1.setDomainName("test.org");
        dms1.setMetricList(dmlist);
        dms2.setDomainName("test.org");
        dms2.setMetricList(dmlist);

        assertEquals("test.org", dms1.getDomainName());
        assertEquals(dmlist, dms1.getMetricList());

        //// equals
        // true case
        assertEquals(dms1, dms1);
        assertEquals(dms1, dms2);

        // false case
        dms2.setMetricList(new ArrayList<>());
        assertNotEquals(dms1, dms2);

        dms2.setDomainName("test.net");
        assertNotEquals(dms1, dms2);

        assertNotEquals("", dms1);
    }

}
