/*
 * Copyright 2020 Verizon Media
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

package com.yahoo.athenz.zts.cert;

import com.yahoo.rdl.JSON;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SshHostCsrTest {
    @Test
    public void testNewCsr() throws IOException {
        SshHostCsr sshHostCsr = JSON.fromBytes(Files.readAllBytes(Paths.get("src/test/resources/sshhost_valid_sample.csr")), SshHostCsr.class);
        Assert.assertNotNull(sshHostCsr);

        sshHostCsr = JSON.fromBytes(Files.readAllBytes(Paths.get("src/test/resources/sshhost_nocnames.csr")), SshHostCsr.class);
        Assert.assertNotNull(sshHostCsr);
        Assert.assertNotNull(sshHostCsr.getReqip());
        Assert.assertNotNull(sshHostCsr.getPubkey());
        Assert.assertNotNull(sshHostCsr.getRequser());
        Assert.assertEquals(sshHostCsr.getCerttype(), "host");
        Assert.assertNotNull(sshHostCsr.getTransid());
    }

}
