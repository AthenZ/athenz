package util

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

const SshSupport = false

func NewSysLogger() (io.Writer, error) {
	return os.Stdout, nil
}

func UpdateFile(fileName string, contents []byte, uid, gid int, perm os.FileMode) error {
	// verify we have valid contents otherwise we're just
	// going to skip and return success without doing anything
	if len(contents) == 0 {
		log.Printf("Contents is empty. Skipping writing to file %s\n", fileName)
		return nil
	}
	// if the original file does not exists then we
	// we just write the contents to the given file
	// directly
	_, err := os.Stat(fileName)
	if err != nil && os.IsNotExist(err) {
		log.Printf("Updating file %s...\n", fileName)
		err = os.WriteFile(fileName, contents, perm)
		if err != nil {
			log.Printf("Unable to write new file %s, err: %v\n", fileName, err)
			return err
		}
	} else {
		timeNano := time.Now().UnixNano()
		// write the new contents to a temporary file
		newFileName := fmt.Sprintf("%s.tmp%d", fileName, timeNano)
		log.Printf("Writing contents to temporary file %s...\n", newFileName)
		err = os.WriteFile(newFileName, contents, perm)
		if err != nil {
			log.Printf("Unable to write new file %s, err: %v\n", newFileName, err)
			return err
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
	}
	return nil
}

func SvcAttrs(username, groupname string) (int, int, int) {
	return 0, 0, 0440
}

func UidGidForUserGroup(username, groupname string) (int, int) {
	return 0, 0
}

func SetupSIADirs(siaMainDir, siaLinkDir string, ownerUid, ownerGid int) error {
	// Create the certs directory, if it doesn't exist
	certDir := fmt.Sprintf("%s/certs", siaMainDir)
	if !FileExists(certDir) {
		err := os.MkdirAll(certDir, 0755)
		if err != nil {
			return fmt.Errorf("unable to create certs dir: %q, error: %v", certDir, err)
		}
	}

	// Create the keys directory, if it doesn't exist
	keyDir := fmt.Sprintf("%s/keys", siaMainDir)
	if !FileExists(keyDir) {
		err := os.MkdirAll(keyDir, 0755)
		if err != nil {
			return fmt.Errorf("unable to create keys dir: %q, error: %v", keyDir, err)
		}
	}
	return nil
}

func SyscallSetGid(gid int) error {
	return nil
}

func SyscallSetUid(uid int) error {
	return nil
}
