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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.zms.config.SolutionTemplates;
import org.testng.annotations.Test;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;

import static org.testng.Assert.assertEquals;

public class SolutionTemplatesSnapshotTest {

    private static final String TEMPLATE_NAME = "solution_templates_snapshot";

    private static SolutionTemplates solutionTemplates() {
        SolutionTemplates solutionTemplates = new SolutionTemplates();
        HashMap<String, Template> templates = new HashMap<>();
        templates.put(TEMPLATE_NAME, new Template().setMetadata(new TemplateMetaData().setLatestVersion(1)));
        solutionTemplates.setTemplates(templates);
        return solutionTemplates;
    }

    @Test
    public void testSolutionTemplatesSnapshotFields() {
        SolutionTemplates solutionTemplates = solutionTemplates();
        SolutionTemplatesSnapshot snapshot = new SolutionTemplatesSnapshot(solutionTemplates,
                Arrays.asList("a", "b"), Paths.get("solution_templates_snapshot.json"), 12345L);
        assertEquals(snapshot.templates, solutionTemplates);
        assertEquals(snapshot.templateNames, Arrays.asList("a", "b"));
        assertEquals(snapshot.path, Paths.get("solution_templates_snapshot.json"));
        assertEquals(snapshot.modifiedMillis, 12345L);
    }
}