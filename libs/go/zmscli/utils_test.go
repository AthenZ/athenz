// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"testing"
)

func TestTokenizer(t *testing.T) {
	cli := Zms{}
	var list []string
	var err error
	list, err = cli.tokenizer("one two three")
	if err != nil {
		t.Error("Tokenizer returned error")
	}
	if len(list) != 3 {
		t.Error("Number of tokens is not 3")
	}
	if list[0] != "one" {
		t.Error("First element is not one")
	}
	if list[1] != "two" {
		t.Error("Second element is not two")
	}
	if list[2] != "three" {
		t.Error("Third element is not three")
	}
	list, err = cli.tokenizer("set-meta-details \"Description is long\" two three")
	if len(list) != 4 {
		t.Error("Number of quoted string tokens is not 4")
	}
	if list[0] != "set-meta-details" {
		t.Error("First element is not set-meta-details")
	}
	if list[1] != "Description is long" {
		t.Error("Second element is not 'Description is long' : " + list[1])
	}
	if list[2] != "two" {
		t.Error("Third element is not two")
	}
	if list[3] != "three" {
		t.Error("Fourth element is not three")
	}
}

func TestIndexOfString(t *testing.T) {
	list := []string{"one", "two", "three", "four"}
	if indexOfString(list, "one") != 0 {
		t.Error("indexOfStrings case 'one' failed")
	}
	if indexOfString(list, "three") != 2 {
		t.Error("indexOfStrings case 'three' failed")
	}
	if indexOfString(list, "four") != 3 {
		t.Error("indexOfStrings case 'four' failed")
	}
	if indexOfString(list, "five") != -1 {
		t.Error("indexOfStrings case 'five' failed")
	}
}

func TestValidatedUsers(t *testing.T) {
	cli := Zms{}
	cli.UserDomain = "user"
	cli.Identity = "user.user1"
	members := []string{"user.user2", "user3"}
	list := cli.validatedUsers(members, false)
	if len(list) != 2 {
		t.Error("Returned list is not length 2")
	}
	if list[0] != "user.user2" {
		t.Error("First member is not user.user2")
	}
	if list[1] != "user.user3" {
		t.Error("Second member is not user.user3")
	}
	list = cli.validatedUsers(members, true)
	if len(list) != 3 {
		t.Error("Returned list is not length 3")
	}
	if list[0] != "user.user2" {
		t.Error("First member is not user.user2")
	}
	if list[1] != "user.user3" {
		t.Error("Second member is not user.user3")
	}
	if list[2] != "user.user1" {
		t.Error("Third member is not user.user1")
	}
	members = []string{"user.user2", "user1"}
	list = cli.validatedUsers(members, false)
	if len(list) != 2 {
		t.Error("Returned list is not length 2")
	}
	if list[0] != "user.user2" {
		t.Error("First member is not user.user2")
	}
	if list[1] != "user.user1" {
		t.Error("Second member is not user.user1")
	}
}

func TestContains(t *testing.T) {
	cli := Zms{}
	list := []string{"one", "two", "three", "four"}
	if !cli.contains(list, "one") {
		t.Error("contains case 'one' failed")
	}
	if !cli.contains(list, "three") {
		t.Error("contains case 'three' failed")
	}
	if !cli.contains(list, "four") {
		t.Error("contains case 'four' failed")
	}
	if cli.contains(list, "five") {
		t.Error("contains case 'five' failed")
	}
}

func TestRemoveAll(t *testing.T) {
	cli := Zms{}
	fullList := []string{"one", "two", "three"}
	removeList := []string{"two", "four"}
	list := cli.RemoveAll(fullList, removeList)
	if len(list) != 2 {
		t.Error("Returned list is not length 2")
	}
	if list[0] != "one" {
		t.Error("First member is not one")
	}
	if list[1] != "three" {
		t.Error("Second member is not three")
	}
	fullList = []string{"two", "four"}
	list = cli.RemoveAll(fullList, removeList)
	if len(list) != 0 {
		t.Error("Returned list is not empty")
	}
}
