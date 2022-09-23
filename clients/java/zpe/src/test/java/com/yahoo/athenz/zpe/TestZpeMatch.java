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
package com.yahoo.athenz.zpe;

import org.testng.annotations.Test;

import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchAll;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchEqual;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchRegex;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchStartsWith;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

public class TestZpeMatch {

    @Test
    public void testGetMatchAll() {
        
        try (ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null)) {
            
            ZpeMatch matchObject = loader.getMatchObject("*");
            assertTrue(matchObject instanceof ZpeMatchAll);
            
            assertTrue(matchObject.matches("abc"));
            assertTrue(matchObject.matches("false"));
            assertTrue(matchObject.matches("whatever"));
        }
    }
    
    @Test
    public void testGetMatchRegex() {
        
        try (ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null)) {
            
            ZpeMatch matchObject = loader.getMatchObject("coretech?test*");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            assertTrue(matchObject.matches("coretechAtest"));
            assertTrue(matchObject.matches("coretechbtestgreat"));
            
            // failures
            
            assertFalse(matchObject.matches("whatever")); // random data
            assertFalse(matchObject.matches("coretechtestgreat")); // missing ?
        }
    }

    @Test
    public void testGetMatchEqual() {
        
        try (ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null)) {
            
            ZpeMatch matchObject = loader.getMatchObject("coretech");
            assertTrue(matchObject instanceof ZpeMatchEqual);
            
            assertTrue(matchObject.matches("coretech"));
            
            // failures
            
            assertFalse(matchObject.matches("whatever")); // random data
            assertFalse(matchObject.matches("coretechA")); // extra A
            assertFalse(matchObject.matches("coretec")); // missing h
        }
    }
    
    @Test
    public void testGetMatchStartsWith() {
        
        try (ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null)) {
            
            ZpeMatch matchObject = loader.getMatchObject("coretech*");
            assertTrue(matchObject instanceof ZpeMatchStartsWith);
            
            assertTrue(matchObject.matches("coretech"));
            assertTrue(matchObject.matches("coretechtest"));
            assertTrue(matchObject.matches("coretechtesttest"));

            // failures
            
            assertFalse(matchObject.matches("whatever")); // random data
            assertFalse(matchObject.matches("coretec")); // missing h
            assertFalse(matchObject.matches("coretecA")); // missing h + extra A
        }
    }
}
