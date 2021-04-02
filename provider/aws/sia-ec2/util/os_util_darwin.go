package util

import (
	"fmt"
	"github.com/AthenZ/athenz/provider/aws/sia-ec2/logutil"
	"io"
	"io/ioutil"
	"log/syslog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const siaUnixGroup = "athenz"
const SshSupport = true

func NewSysLogger() (io.Writer, error) {
	return syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
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
	if uid != 0 || gid != 0 {
		logutil.LogInfo(sysLogger, "Changing file %s ownership to %d:%d...\n", fileName, uid, gid)
		err = os.Chown(fileName, uid, gid)
		if err != nil {
			logutil.LogInfo(sysLogger, "Cannot chown file %s to %d:%d, err: %v\n", fileName, uid, gid, err)
			return err
		}
	}
	return nil
}

func SvcAttrs(username, groupname string, sysLogger io.Writer) (int, int, int) {
	// Default file mode for service key
	fileMode := 0400
	// Get uid and gid for the username.
	uid, gid := uidGidForUser(username, sysLogger)

	// Override the group id if user explicitly specified the group.
	ggid := -1
	if groupname != "" {
		ggid = gidForGroup(groupname, sysLogger)
	}
	// if the group is not specified or invalid then we'll default
	// to our unix group name called athenz
	if ggid == -1 {
		ggid = gidForGroup(siaUnixGroup, sysLogger)
	}
	// if we have a valid value then update the gid
	// otherwise use the user group id value
	if ggid != -1 {
		gid = ggid
	}
	if gid != -1 {
		fileMode = 0440
	}
	return uid, gid, fileMode
}

func gidForGroup(groupname string, sysLogger io.Writer) int {
	//shelling out to id is used here because the os/user package
	//requires cgo, which doesn't cross-compile. we can use getent group
	//command but instead we opted for a simple grep for /etc/group
	cmdStr := fmt.Sprintf("^%s:", groupname)
	out, err := exec.Command("/usr/bin/grep", cmdStr, "/etc/group").Output()
	if err != nil {
		logutil.LogInfo(sysLogger, "Cannot exec '/usr/bin/grep %s '/etc/group': %v\n", groupname, err)
		return -1
	}
	s := strings.Trim(string(out), "\n\r ")
	comps := strings.Split(string(out), ":")
	if len(comps) < 3 {
		logutil.LogInfo(sysLogger, "Invalid response from grep group command: %s\n", s)
		return -1
	}
	//the group id should be the third value: 'group_name:password:group_id:group_list'
	id, err := strconv.Atoi(comps[2])
	if err != nil {
		logutil.LogInfo(sysLogger, "Invalid response from getent group command: %s\n", s)
		return -1
	}
	return id
}

func idCommand(username, arg string, sysLogger io.Writer) int {
	//shelling out to id is used here because the os/user package
	//requires cgo, which doesn't cross-compile
	out, err := exec.Command("id", arg, username).Output()
	if err != nil {
		logutil.LogFatal(sysLogger, "Cannot exec 'id %s %s': %v\n", arg, username, err)
	}
	s := strings.Trim(string(out), "\n\r ")
	id, err := strconv.Atoi(s)
	if err != nil {
		logutil.LogFatal(sysLogger, "Unexpected UID/GID format in user record: %s\n", string(out))
	}
	return id
}

func uidGidForUser(username string, sysLogger io.Writer) (int, int) {
	if username == "" {
		return 0, 0
	}
	uid := idCommand(username, "-u", sysLogger)
	gid := idCommand(username, "-g", sysLogger)
	return uid, gid
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

	//make sure the link directory exists as well
	if siaLinkDir != "" && !FileExists(siaLinkDir) {
		err := os.Symlink(siaMainDir, siaLinkDir)
		if err != nil {
			logutil.LogInfo(sysLogger, "Unable to symlink SIA directory '%s': %v\n", siaLinkDir, err)
			return nil
		}
	}
	return nil
}
