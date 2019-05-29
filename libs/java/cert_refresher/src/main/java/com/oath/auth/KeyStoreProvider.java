/*
 * Copyright 2017 Yahoo Holdings, Inc.
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
package com.oath.auth;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;

/**
 * Interface to provide a KeyStore object which could be
 * either a PrivateKey/Certificate key pair store or a
 * Trust CA Certificate store
 */
public interface KeyStoreProvider {

    KeyStore provide() throws KeyRefresherException, FileNotFoundException, IOException;
}

