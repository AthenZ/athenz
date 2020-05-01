package siafile

import (
	"bytes"
	"fmt"
	"github.com/yahoo/athenz/libs/go/sia/verify"
	"io/ioutil"
	"log"
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
	// we just write the contents to the given file
	// directly
	stat, err := os.Stat(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Updating file %s...\n", fileName)
			err = ioutil.WriteFile(fileName, contents, perm)
			if err != nil {
				log.Printf("Unable to write new file %s, err: %v\n", fileName, err)
				return err
			}
		} else {
			// Unknown stat error
			log.Printf("Unable to stat file: %q", fileName)
			return err
		}
	} else {
		// Skip updating file if it's identical to existing file
		oldBytes, err := ioutil.ReadFile(fileName)
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
		log.Printf("Not changing the file ownership, file: %q, uid: %d, gid: %d", fileName, uid, gid)
	}
	return nil
}

// overrideFile replaces existing file with new content (after verifying the content is valid)
func overrideFile(fileName string, err error, contents []byte, perm os.FileMode, vfn verify.VerifyFn) error {
	timeNano := time.Now().UnixNano()
	// write the new contents to a temporary file
	newFileName := fmt.Sprintf("%s.tmp%d", fileName, timeNano)
	log.Printf("Writing contents to temporary file %s...\n", newFileName)
	err = ioutil.WriteFile(newFileName, contents, perm)
	if err != nil {
		log.Printf("Unable to write new file %s, err: %v\n", newFileName, err)
		return err
	}

	// Sanity check the new file against the existing one
	if vfn != nil {
		err = vfn(fileName, newFileName)
		if err != nil {
			log.Printf("invalid content: %q, error: %v", newFileName, err)
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
