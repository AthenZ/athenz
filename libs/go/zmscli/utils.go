// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bufio"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
)

func split(data []byte, atEOF bool) (advance int, token []byte, err error) {

	// create a split function using the existing word scanner
	// we're going to look for the quoted strings and handle them accordingly

	advance, token, err = bufio.ScanWords(data, atEOF)
	if err == nil && token != nil {
		if token[0] == '"' {
			var advance_fwd int
			var token_fwd []byte
			for {
				advance_fwd, token_fwd, err = bufio.ScanWords(data[advance:], atEOF)
				if err != nil || token_fwd == nil {
					return
				}
				advance += advance_fwd
				token = append(token, 32)
				token = append(token, token_fwd...)
				if token_fwd[len(token_fwd)-1] == '"' {
					token = token[1 : len(token)-1]
					break
				}
			}
		}
	}
	return
}

func (cli Zms) createResourceList(items []string) []zms.ResourceName {
	list := make([]zms.ResourceName, 0)
	for _, item := range items {
		list = append(list, zms.ResourceName(item))
	}
	return list
}

func (cli Zms) createStringList(items []zms.ResourceName) []string {
	list := make([]string, 0)
	for _, item := range items {
		list = append(list, string(item))
	}
	return list
}

func (cli Zms) tokenizer(input string) ([]string, error) {

	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(split)

	tokens := make([]string, 0)
	for scanner.Scan() {
		tokens = append(tokens, scanner.Text())
	}
	err := scanner.Err()
	return tokens, err
}

func indexOfString(s []string, match string) int {
	for i, ss := range s {
		if ss == match {
			return i
		}
	}
	return -1
}

func (cli Zms) validatedUsers(users []string, forceSelf bool) []string {
	validatedUsers := make([]string, 0)
	for _, v := range users {
		if strings.Index(v, ".") < 0 {
			validatedUsers = append(validatedUsers, cli.UserDomain+"."+v)
		} else {
			validatedUsers = append(validatedUsers, v)
		}
	}
	if forceSelf && indexOfString(validatedUsers, cli.Identity) < 0 {
		validatedUsers = append(validatedUsers, cli.Identity)
	}
	return validatedUsers
}

func (cli Zms) contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (cli Zms) RemoveAll(fullList []string, removeList []string) []string {
	var newList []string
	for _, item := range fullList {
		if !cli.contains(removeList, item) {
			newList = append(newList, item)
		}
	}
	return newList
}
