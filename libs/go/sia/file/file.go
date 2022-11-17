// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package siafile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/libs/go/sia/verify"
	"os"
	"time"
)

func Update(fileName string, contents []byte, uid, gid int, perm os.FileMode, vfn verify.VerifyFn) error {
	// verify we have valid contents otherwise we're just
	// going to skip and return success without doing anything
	if len(contents) == 0 {
		log.Printf("Contents is empty. Skipping writing to file %s\n", fileName)
		return nil
	}
	// if the original file does not exists then we
	// just write the contents to the given file
	// directly
	stat, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Updating file %s...\n", fileName)
			err = os.WriteFile(fileName, contents, perm)
			if err != nil {
				log.Printf("Unable to write new file %s, err: %v\n", fileName, err)
				return err
			}
		} else {
			// Unknown stat error
			log.Printf("Unable to stat file: %q\n", fileName)
			return err
		}
	} else {
		// Skip updating file if it's identical to the existing file
		oldBytes, err := os.ReadFile(fileName)
		if bytes.Equal(oldBytes, contents) {
			log.Printf("File contents hasn't changed. Skipping writing to file %s\n", fileName)
			// Change permissions only if needed (minimizing mtime / ctime changes in the file)
			if stat.Mode() != perm {
				err = os.Chmod(fileName, perm)
				if err != nil {
					log.Fatalf("Cannot chmod file %s to %d, err: %v", fileName, perm, err)
					return err
				}
			}
		} else {
			err = overrideFile(fileName, err, contents, perm, vfn)
			if err != nil {
				return err
			}
		}
	}
	if uid != 0 || gid != 0 {
		log.Printf("Changing file %s ownership to %d:%d...\n", fileName, uid, gid)
		err = os.Chown(fileName, uid, gid)
		if err != nil {
			log.Fatalf("Cannot chown file %s to %d:%d, err: %v", fileName, uid, gid, err)
			return err
		}
	} else {
		log.Printf("Not changing the file ownership, file: %q, uid: %d, gid: %d\n", fileName, uid, gid)
	}
	return nil
}

// overrideFile replaces existing file with new content (after verifying the content is valid)
func overrideFile(fileName string, err error, contents []byte, perm os.FileMode, vfn verify.VerifyFn) error {
	timeNano := time.Now().UnixNano()
	// write the new contents to a temporary file
	newFileName := fmt.Sprintf("%s.tmp%d", fileName, timeNano)
	log.Printf("Writing contents to temporary file %s...\n", newFileName)
	err = os.WriteFile(newFileName, contents, perm)
	if err != nil {
		log.Printf("Unable to write new file %s, err: %v\n", newFileName, err)
		return err
	}

	// Sanity check the new file against the existing one
	if vfn != nil {
		err = vfn(fileName, newFileName)
		if err != nil {
			log.Printf("invalid content: %q, error: %v\n", newFileName, err)
			return err
		}
	}

	// move the contents of the old file to a backup file
	bakFileName := fmt.Sprintf("%s.bak%d", fileName, timeNano)
	log.Printf("Renaming original file %s to backup file %s...\n", fileName, bakFileName)
	err = os.Rename(fileName, bakFileName)
	if err != nil {
		log.Printf("Unable to rename file %s to %s, err: %v\n", fileName, bakFileName, err)
		return err
	}
	// move the new contents to the original location
	log.Printf("Renaming temporary file %s to requested file %s...\n", newFileName, fileName)
	err = os.Rename(newFileName, fileName)
	if err != nil {
		log.Printf("Unable to rename file %s to %s, err: %v\n", newFileName, fileName, err)
		// before returning try to restore the original file
		os.Rename(bakFileName, fileName)
		return err
	}
	// remove the temporary backup file
	log.Printf("Removing backup file %s...\n", bakFileName)
	os.Remove(bakFileName)
	return nil
}

func Copy(sourceFile, destFile string, perm os.FileMode) error {
	if Exists(sourceFile) {
		sourceBytes, err := os.ReadFile(sourceFile)
		if err != nil {
			log.Printf("unable to read file %s\n", sourceFile)
			return err
		}
		err = os.WriteFile(destFile, sourceBytes, perm)
		if err != nil {
			log.Printf("unable to write to file %s\n", destFile)
			return err
		}
	}
	return nil
}

func CopyCertKeyFile(srcKey, destKey, srcCert, destCert string, keyPerm, certPerm int) error {
	err := Copy(srcKey, destKey, os.FileMode(keyPerm))
	if err != nil {
		return err
	}

	err = Copy(srcCert, destCert, os.FileMode(certPerm))
	if err != nil {
		return err
	}
	return nil
}

func Exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func WriteFile(content interface{}, ipFile string) error {
	file, err := json.MarshalIndent(content, "", " ")
	if err == nil {
		err = os.WriteFile(ipFile, file, 0644)
		if err != nil {
			log.Printf("Failed to write file, Error: %v\n", err)
			return err
		}
	} else {
		log.Printf("Failed marshal struct, Error: %v\n", err)
		return err
	}
	return nil
}

func ReadFile(filePath string, value interface{}) error {

	file, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read file: %v\n", err)
		return err
	}

	err = json.Unmarshal(file, value)
	if err != nil {
		log.Printf("Failed to unmarshal file: %v\n", err)
		return err
	}
	return nil
}
