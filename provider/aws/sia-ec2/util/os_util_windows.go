package util

import (
	"fmt"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/logutil"
	"io"
	"io/ioutil"
	"os"
	"time"
)

const SshSupport = false

func NewSysLogger() (io.Writer, error) {
	return os.Stdout, nil
}

func UpdateFile(fileName string, contents []byte, uid, gid int, perm os.FileMode, sysLogger io.Writer) error {
	// verify we have valid contents otherwise we're just
	// going to skip and return success without doing anything
	if len(contents) == 0 {
		logutil.LogInfo(sysLogger, "Contents is empty. Skipping writing to file %s\n", fileName)
		return nil
	}
	// if the original file does not exists then we
	// we just write the contents to the given file
	// directly
	_, err := os.Stat(fileName)
	if err != nil && os.IsNotExist(err) {
		logutil.LogInfo(sysLogger, "Updating file %s...\n", fileName)
		err = ioutil.WriteFile(fileName, contents, perm)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to write new file %s, err: %v\n", fileName, err)
			return err
		}
	} else {
		timeNano := time.Now().UnixNano()
		// write the new contents to a temporary file
		newFileName := fmt.Sprintf("%s.tmp%d", fileName, timeNano)
		logutil.LogInfo(sysLogger, "Writing contents to temporary file %s...\n", newFileName)
		err = ioutil.WriteFile(newFileName, contents, perm)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to write new file %s, err: %v\n", newFileName, err)
			return err
		}
		// move the contents of the old file to a backup file
		bakFileName := fmt.Sprintf("%s.bak%d", fileName, timeNano)
		logutil.LogInfo(sysLogger, "Renaming original file %s to backup file %s...\n", fileName, bakFileName)
		err = os.Rename(fileName, bakFileName)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to rename file %s to %s, err: %v\n", fileName, bakFileName, err)
			return err
		}
		// move the new contents to the original location
		logutil.LogInfo(sysLogger, "Renaming temporary file %s to requested file %s...\n", newFileName, fileName)
		err = os.Rename(newFileName, fileName)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to rename file %s to %s, err: %v\n", newFileName, fileName, err)
			// before returning try to restore the original file
			os.Rename(bakFileName, fileName)
			return err
		}
		// remove the temporary backup file
		logutil.LogInfo(sysLogger, "Removing backup file %s...\n", bakFileName)
		os.Remove(bakFileName)
	}
	return nil
}

func SvcAttrs(username, groupname string, sysLogger io.Writer) (int, int, int) {
	return 0, 0, 0440
}

func SetupSIADirs(siaMainDir, siaLinkDir string, sysLogger io.Writer) error {
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
