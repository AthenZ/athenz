// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zms"
	"gopkg.in/yaml.v2"
)

// parseBundleFileArg parses a bundle file argument in the format
// local_path[=bundle_path]. If the bundle path is not specified, the
// local path (which must then be relative) is used as the path in the bundle.
func parseBundleFileArg(arg string) (string, string, error) {
	localPath := arg
	bundlePath := arg
	if idx := strings.Index(arg, "="); idx != -1 {
		localPath = arg[:idx]
		bundlePath = arg[idx+1:]
	}
	if localPath == "" || bundlePath == "" {
		return "", "", fmt.Errorf("invalid bundle file argument: %s", arg)
	}
	bundlePath = path.Clean(strings.ReplaceAll(bundlePath, "\\", "/"))
	if path.IsAbs(bundlePath) || bundlePath == ".." || strings.HasPrefix(bundlePath, "../") {
		return "", "", fmt.Errorf("bundle file path must be relative to the bundle root: %s", bundlePath)
	}
	return localPath, bundlePath, nil
}

func readBundleFile(arg string) (*zms.PolicyBundleFile, error) {
	localPath, bundlePath, err := parseBundleFileArg(arg)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(localPath)
	if err != nil {
		return nil, err
	}
	return &zms.PolicyBundleFile{
		Path:    bundlePath,
		Content: string(content),
	}, nil
}

func readBundleFiles(args []string) ([]*zms.PolicyBundleFile, error) {
	files := make([]*zms.PolicyBundleFile, 0, len(args))
	for _, arg := range args {
		file, err := readBundleFile(arg)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func (cli Zms) yamlOutput(res interface{}) (*string, error) {
	output, err := yaml.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("failed to produce YAML output: %v", err)
	}
	s := string(output)
	return &s, nil
}

func (cli Zms) successMessage(msg string) (*string, error) {
	message := SuccessMessage{
		Status:  200,
		Message: msg,
	}
	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ListPolicyBundles(dn string) (*string, error) {
	list, err := cli.Zms.GetPolicyBundleList(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	return cli.dumpByFormat(list, cli.yamlOutput)
}

func (cli Zms) ShowPolicyBundle(dn string, bn string, version string) (*string, error) {
	var bundle *zms.PolicyBundle
	var err error
	if version == "" {
		bundle, err = cli.Zms.GetPolicyBundle(zms.DomainName(dn), zms.EntityName(bn))
	} else {
		bundle, err = cli.Zms.GetPolicyBundleVersion(zms.DomainName(dn), zms.EntityName(bn), zms.SimpleName(version))
	}
	if err != nil {
		return nil, err
	}
	return cli.dumpByFormat(bundle, cli.yamlOutput)
}

func (cli Zms) ListPolicyBundleVersions(dn string, bn string) (*string, error) {
	list, err := cli.Zms.GetPolicyBundleVersionList(zms.DomainName(dn), zms.EntityName(bn))
	if err != nil {
		return nil, err
	}
	return cli.dumpByFormat(list, cli.yamlOutput)
}

func (cli Zms) putPolicyBundle(dn string, bn string, engine string, version string, fileArgs []string) (*string, error) {
	files, err := readBundleFiles(fileArgs)
	if err != nil {
		return nil, err
	}
	bundle := zms.PolicyBundle{
		Name:   zms.ResourceName(dn + ":bundle." + bn),
		Engine: zms.SimpleName(engine),
		Files:  files,
	}
	if version != "" {
		bundle.Version = zms.SimpleName(version)
	}
	returnObj := true
	updated, err := cli.Zms.PutPolicyBundle(zms.DomainName(dn), zms.EntityName(bn), cli.AuditRef, &returnObj, &bundle)
	if err != nil {
		return nil, err
	}
	if updated != nil {
		return cli.dumpByFormat(summarizePolicyBundle(updated), cli.yamlOutput)
	}
	output, err := cli.ShowPolicyBundle(dn, bn, version)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowPolicyBundle(dn, bn, version)
	}
	return output, err
}

// summarizePolicyBundle returns a copy of the bundle without the file
// content so the output after an update is not the full source
func summarizePolicyBundle(bundle *zms.PolicyBundle) *zms.PolicyBundle {
	summary := *bundle
	summary.Files = make([]*zms.PolicyBundleFile, 0, len(bundle.Files))
	for _, file := range bundle.Files {
		summary.Files = append(summary.Files, &zms.PolicyBundleFile{Path: file.Path, Sha256: file.Sha256})
	}
	return &summary
}

func (cli Zms) AddPolicyBundle(dn string, bn string, engine string, fileArgs []string) (*string, error) {
	return cli.putPolicyBundle(dn, bn, engine, "", fileArgs)
}

func (cli Zms) AddPolicyBundleVersion(dn string, bn string, version string, engine string, fileArgs []string) (*string, error) {
	return cli.putPolicyBundle(dn, bn, engine, version, fileArgs)
}

func (cli Zms) CopyPolicyBundleVersion(dn string, bn string, version string, fromVersion string) (*string, error) {
	options := zms.PolicyBundleOptions{
		Version: zms.SimpleName(version),
	}
	if fromVersion != "" {
		options.FromVersion = zms.SimpleName(fromVersion)
	}
	returnObj := false
	_, err := cli.Zms.PutPolicyBundleVersion(zms.DomainName(dn), zms.EntityName(bn), &options, cli.AuditRef, &returnObj)
	if err != nil {
		return nil, err
	}
	return cli.successMessage("[Created bundle: " + dn + ":bundle." + bn + " version: " + version + "]")
}

func (cli Zms) AddPolicyBundleFile(dn string, bn string, fileArg string) (*string, error) {
	file, err := readBundleFile(fileArg)
	if err != nil {
		return nil, err
	}
	err = cli.Zms.PutPolicyBundleFile(zms.DomainName(dn), zms.EntityName(bn), cli.AuditRef, file)
	if err != nil {
		return nil, err
	}
	return cli.successMessage("[Added file: " + file.Path + " to bundle: " + dn + ":bundle." + bn + "]")
}

func (cli Zms) DeletePolicyBundleFile(dn string, bn string, path string) (*string, error) {
	err := cli.Zms.DeletePolicyBundleFile(zms.DomainName(dn), zms.EntityName(bn), path, cli.AuditRef)
	if err != nil {
		return nil, err
	}
	return cli.successMessage("[Deleted file: " + path + " from bundle: " + dn + ":bundle." + bn + "]")
}

func (cli Zms) SetActivePolicyBundleVersion(dn string, bn string, version string) (*string, error) {
	options := zms.PolicyBundleOptions{
		Version: zms.SimpleName(version),
	}
	err := cli.Zms.SetActivePolicyBundleVersion(zms.DomainName(dn), zms.EntityName(bn), &options, cli.AuditRef)
	if err != nil {
		return nil, err
	}
	return cli.successMessage("[Activated bundle: " + dn + ":bundle." + bn + " version: " + version + "]")
}

func (cli Zms) DeletePolicyBundleVersion(dn string, bn string, version string) (*string, error) {
	err := cli.Zms.DeletePolicyBundleVersion(zms.DomainName(dn), zms.EntityName(bn), zms.SimpleName(version), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	return cli.successMessage("[Deleted bundle: " + dn + ":bundle." + bn + " version: " + version + "]")
}

func (cli Zms) DeletePolicyBundle(dn string, bn string) (*string, error) {
	err := cli.Zms.DeletePolicyBundle(zms.DomainName(dn), zms.EntityName(bn), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	return cli.successMessage("[Deleted bundle: " + dn + ":bundle." + bn + "]")
}
