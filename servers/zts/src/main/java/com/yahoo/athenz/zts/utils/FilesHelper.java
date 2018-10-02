/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.zts.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

public class FilesHelper {

    public Path write(File file, byte[] data) throws IOException {
        return Files.write(file.toPath(), data);
    }

    public void delete(File file) throws IOException {
        Files.delete(file.toPath());
    }

    public Path setPosixFilePermissions(File file, Set<PosixFilePermission> perms)
            throws IOException {
        return Files.setPosixFilePermissions(file.toPath(), perms);
    }

    public void createEmptyFile(File file) throws IOException {
        new FileOutputStream(file).close();
        //noinspection ResultOfMethodCallIgnored
        file.setLastModified(System.currentTimeMillis());
    }
}
