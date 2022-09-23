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

import java.util.HashMap;
import java.util.Set;
import com.yahoo.athenz.zms.Template;

public class SolutionTemplates {
    private HashMap<String, Template> templates;

    public HashMap<String, Template> getTemplates() {
        return templates;
    }

    public void setTemplates(HashMap<String, Template> templates) {
        this.templates = templates;
    }
    
    public Template get(String name) {
        return templates.get(name);
    }
    
    public boolean contains(String name) {
        return templates.containsKey(name);
    }
    
    public Set<String> names() {
        return templates.keySet();
    }
}
