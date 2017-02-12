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
package com.yahoo.athenz.zpe;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchAll;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchEqual;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchRegex;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchStartsWith;

import static org.testng.Assert.assertTrue;

import java.io.File;

public class TestZpeUpdPolLoader {

    static String TEST_POL_DIR  = "./src/test/resources/upd_pol_dir/";
    static String TEST_POL_FILE = "angler.pol";
    static String TEST_POL_GOOD_FILE = "./src/test/resources/pol_dir/angler.pol";
    
    static String TEST_POL_FILE_EMPTY      = "empty.pol";
    static String TEST_POL_GOOD_FILE_EMPTY = "./src/test/resources/pol_dir/empty.pol";

    @Test
    public void testGetMatchObject() {
        
        try (ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null)) {
            
            ZpeMatch matchObject = loader.getMatchObject("*");
            assertTrue(matchObject instanceof ZpeMatchAll);
            
            matchObject = loader.getMatchObject("**");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("?*");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("?");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("test?again*");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("*test");
            assertTrue(matchObject instanceof ZpeMatchRegex);
            
            matchObject = loader.getMatchObject("test");
            assertTrue(matchObject instanceof ZpeMatchEqual);
            
            matchObject = loader.getMatchObject("(test|again)");
            assertTrue(matchObject instanceof ZpeMatchEqual);
            
            matchObject = loader.getMatchObject("test*");
            assertTrue(matchObject instanceof ZpeMatchStartsWith);
        }
    }

    @Test
    public void testLoadDb() throws Exception {

        System.out.println("TestZpeUpdPolLoader: testLoadDb: dir=" + TEST_POL_DIR);

        java.nio.file.Path dirPath  = java.nio.file.Paths.get(TEST_POL_DIR);
        try {
            java.nio.file.Files.createDirectory(dirPath);
        } catch (java.nio.file.FileAlreadyExistsException exc) {
        }

        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);

        java.nio.file.Path badFile  = java.nio.file.Paths.get(TEST_POL_DIR, TEST_POL_FILE);
        java.nio.file.Files.deleteIfExists(badFile);
        java.io.File polFile = new java.io.File(TEST_POL_DIR, TEST_POL_FILE);
        polFile.createNewFile();
        java.io.File [] files = { polFile };
        loader.loadDb(files);

        long lastModMilliSeconds = polFile.lastModified();
        java.util.Map<String, ZpeUpdPolLoader.ZpeFileStatus> fsmap = loader.getFileStatusMap();
        ZpeUpdPolLoader.ZpeFileStatus fstat = fsmap.get(polFile.getName());
        assertTrue(fstat.validPolFile == false);

        // move good policy file over the bad one
        java.nio.file.Path goodFile = java.nio.file.Paths.get(TEST_POL_GOOD_FILE);
        java.nio.file.Files.copy(goodFile, badFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        loader.loadDb(files);
        long lastModMilliSeconds2 = polFile.lastModified();
        fsmap = loader.getFileStatusMap();
        fstat = fsmap.get(polFile.getName());
        assertTrue(fstat.validPolFile == true);
        loader.close();
        System.out.println("TestZpeUpdPolLoader: testLoadDb: timestamp1=" + lastModMilliSeconds + " timestamp2=" + lastModMilliSeconds2);
    }
    
    @Test
    public void testLoadDBNull() {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        loader.loadDb(null);
        
        loader.close();
    }
    
    @Test
    public void testLoadDBNotExist() throws Exception {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(TEST_POL_DIR);
        File fileMock = Mockito.mock(File.class);
        java.io.File [] files = { fileMock };
        
        // delete file
        Mockito.when(fileMock.exists()).thenReturn(false);
        
        try {
            loader.loadDb(files);
        } catch(Exception ex) {
            loader.close();
        }
        
        loader.close();
    }
    
    @Test(expectedExceptions = {java.lang.Exception.class})
    public void testStartNullDir() throws Exception {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader(null);
        loader.start();
        loader.close();
    }
    
    @Test
    public void testLoadFileStatusNull() {
        ZpeUpdPolLoader loader = new ZpeUpdPolLoader("./noexist");
        ZpeUpdMonitor monitor = new ZpeUpdMonitor(loader);
        File[] files = monitor.loadFileStatus();
        assertTrue(files == null);
        loader.close();
    }
    
    @Test
    public void testUpdLoaderInvalid() {
        ZpeUpdPolLoader loaderMock = Mockito.mock(ZpeUpdPolLoader.class);
        Mockito.when(loaderMock.getDirName()).thenReturn(null);
        ZpeUpdMonitor monitor = new ZpeUpdMonitor(loaderMock);
                
        // TODO: validate log message
        monitor.run();
        monitor.cancel();
        monitor.run();
    }
}
