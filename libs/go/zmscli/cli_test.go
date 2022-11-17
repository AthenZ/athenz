// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zms"
	"os"
	"testing"
)

func TestGetTimeStamp(t *testing.T) {
	data := "2017-03-02T15:04:00Z"
	value, err := getTimestamp(data)
	if err != nil {
		t.Error("could not parse timestamp:", err)
	} else {
		t.Log(value)
	}
}

func loadTestData(test *testing.T, filename string) *map[string]interface{} {
	var data map[string]interface{}
	bytes, err := os.ReadFile("testdata/" + filename)
	if err != nil {
		fmt.Printf("Cannot read data(%s): %v", filename, err)
		test.Errorf("Cannot read data(%s): %v", filename, err)
		return nil
	} else if err = json.Unmarshal(bytes, &data); err != nil {
		fmt.Printf("Cannot unmarshal data (%s): %v", filename, err)
		test.Errorf("Cannot unmarshal data (%s): %v", filename, err)
		return nil
	} else {
		fmt.Println("loaded", filename)
		return &data
	}
}

func TestDumpByFormatJson(t *testing.T) {
	cli := Zms{
		OutputFormat: "json",
	}
	roleData := loadTestData(t, "role_test.json")
	expectedBytes, _ := os.ReadFile("testdata/expected_role_json.json")
	value, _ := cli.dumpByFormat(roleData, cli.buildYAMLOutput)

	if *value != string(expectedBytes) {
		t.Errorf("Expected value:\n %s \n, received value:\n %s \n", string(expectedBytes), *value)
	} else {
		t.Log("Success!")
	}
}

func TestDumpByFormatYaml(t *testing.T) {
	cli := Zms{
		OutputFormat: "yaml",
	}
	roleData := loadTestData(t, "role_test.json")
	expectedBytes, _ := os.ReadFile("testdata/expected_role_yaml.yaml")
	value, _ := cli.dumpByFormat(roleData, nil)
	if *value != string(expectedBytes) {
		t.Errorf("Expected value:\n %s \n, received value:\n %s \n", string(expectedBytes), *value)
	} else {
		t.Log("Success!")
	}
}

func TestDumpByFormatOldYaml(t *testing.T) {
	cli := Zms{
		OutputFormat: "manualYaml",
	}
	roleData := loadTestData(t, "role_test.json")
	expectedBytes, _ := os.ReadFile("testdata/expected_role_yaml_old.yaml")

	jsonbody, err := json.Marshal(roleData)
	if err != nil {
		// do error check
		t.Error(err)
		return
	}
	role := zms.Role{}
	if err := json.Unmarshal(jsonbody, &role); err != nil {
		// do error check
		fmt.Println(err)
		return
	}

	auditLog := false
	oldYamlConverter := func(res interface{}) (*string, error) {
		jsonbody, err := json.Marshal(res)
		if err != nil {
			// do error check
			t.Error(err)
			return nil, err
		}
		role := zms.Role{}
		if err := json.Unmarshal(jsonbody, &role); err != nil {
			// do error check
			fmt.Println(err)
			return nil, err
		}

		var buf bytes.Buffer
		buf.WriteString("role:\n")
		cli.dumpRole(&buf, role, auditLog, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	value, _ := cli.dumpByFormat(roleData, oldYamlConverter)

	if *value != string(expectedBytes) {
		t.Errorf("Expected value:\n %s \n, received value:\n %s \n", string(expectedBytes), *value)
	} else {
		t.Log("Success!")
	}
}
