// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zms

import (
	"fmt"
	"strings"
)

const (
	// BulkDeleteChunkSize is the maximum number of names for one bulk delete request.
	BulkDeleteChunkSize = 250
	// BulkDeleteMaxPathParamLength is the maximum path parameter length for one bulk delete request.
	BulkDeleteMaxPathParamLength = 6000
)

func bulkDeleteNameListChunks(names []EntityName, objectType string) ([]EntityNameList, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no %s names specified", objectType)
	}

	chunks := make([]EntityNameList, 0, (len(names)+BulkDeleteChunkSize-1)/BulkDeleteChunkSize)
	chunk := make([]string, 0, BulkDeleteChunkSize)
	normalizedNames := make(map[string]struct{}, len(names))
	pathParamLength := 0

	for _, name := range names {
		entityName := string(name)
		entityNameLength := len(entityName)
		if entityNameLength > BulkDeleteMaxPathParamLength {
			return nil, fmt.Errorf("%s name exceeds maximum path parameter length", objectType)
		}
		normalizedName := strings.ToLower(entityName)
		if _, ok := normalizedNames[normalizedName]; ok {
			continue
		}
		normalizedNames[normalizedName] = struct{}{}

		nextLength := entityNameLength
		if len(chunk) > 0 {
			nextLength++
		}
		if len(chunk) > 0 && (len(chunk) == BulkDeleteChunkSize ||
			pathParamLength+nextLength > BulkDeleteMaxPathParamLength) {
			chunks = append(chunks, EntityNameList(strings.Join(chunk, ",")))
			chunk = chunk[:0]
			pathParamLength = 0
			nextLength = entityNameLength
		}

		chunk = append(chunk, entityName)
		pathParamLength += nextLength
	}

	if len(chunk) > 0 {
		chunks = append(chunks, EntityNameList(strings.Join(chunk, ",")))
	}

	return chunks, nil
}

func (client ZMSClient) deleteNameListInChunks(names []EntityName, objectType string,
	deleteAction func(EntityNameList) error) error {

	chunks, err := bulkDeleteNameListChunks(names, objectType)
	if err != nil {
		return err
	}

	for _, chunk := range chunks {
		if err := deleteAction(chunk); err != nil {
			return err
		}
	}
	return nil
}

// DeleteRoleList deletes the specified roles from a domain in bounded bulk requests.
func (client ZMSClient) DeleteRoleList(domainName DomainName, roleNames []EntityName,
	auditRef string, resourceOwner string) error {

	return client.deleteNameListInChunks(roleNames, "role", func(names EntityNameList) error {
		return client.DeleteRoles(domainName, names, auditRef, resourceOwner)
	})
}

// DeletePolicyList deletes the specified policies from a domain in bounded bulk requests.
func (client ZMSClient) DeletePolicyList(domainName DomainName, policyNames []EntityName,
	auditRef string, resourceOwner string) error {

	return client.deleteNameListInChunks(policyNames, "policy", func(names EntityNameList) error {
		return client.DeletePolicies(domainName, names, auditRef, resourceOwner)
	})
}
