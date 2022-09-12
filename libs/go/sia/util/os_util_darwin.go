package util

import (
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const siaUnixGroup = "athenz"
const SshSupport = true

func NewSysLogger() (io.Writer, error) {
	return syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "siad")
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
		err = ioutil.WriteFile(fileName, contents, perm)
		if err != nil {
			log.Printf("Unable to write new file %s, err: %v\n", fileName, err)
			return err
		}
	} else {
		timeNano := time.Now().UnixNano()
		// write the new contents to a temporary file
		newFileName := fmt.Sprintf("%s.tmp%d", fileName, timeNano)
		log.Printf("Writing contents to temporary file %s...\n", newFileName)
		err = ioutil.WriteFile(newFileName, contents, perm)
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
	currentUid, currentGid := uidGidForUser("")
	if currentUid != uid || currentGid != gid {
		log.Printf("Changing file %s ownership to %d:%d...\n", fileName, uid, gid)
		err = os.Chown(fileName, uid, gid)
		if err != nil {
			log.Printf("Cannot chown file %s to %d:%d, err: %v\n", fileName, uid, gid, err)
			return err
		}
	}
	return nil
}

func SvcAttrs(username, groupname string) (int, int, int) {
	// Default file mode for service key
	fileMode := 0400
	// Get uid and gid for the username.
	uid, gid := uidGidForUser(username)

	// Override the group id if user explicitly specified the group.
	ggid := -1
	if groupname != "" {
		ggid = gidForGroup(groupname)
	}
	// if the group is not specified or invalid then we'll default
	// to our unix group name called athenz
	if ggid == -1 {
		ggid = gidForGroup(siaUnixGroup)
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

func UidGidForUserGroup(username, groupname string) (int, int) {
	// Get uid and gid for the username.
	uid, gid := uidGidForUser(username)

	// Override the group id if user explicitly specified the group.
	ggid := -1
	if groupname != "" {
		ggid = gidForGroup(groupname)
	}
	// if the group is not specified or invalid then we'll default
	// to our unix group name called athenz
	if ggid == -1 {
		ggid = gidForGroup(siaUnixGroup)
	}
	// if we have a valid value then update the gid
	// otherwise use the user group id value
	if ggid != -1 {
		gid = ggid
	}
	return uid, gid
}

func gidForGroup(groupname string) int {
	//shelling out to id is used here because the os/user package
	//requires cgo, which doesn't cross-compile. we can use getent group
	//command but instead we opted for a simple grep for /etc/group
	cmdStr := fmt.Sprintf("^%s:", groupname)
	out, err := exec.Command(GetUtilPath("grep"), cmdStr, "/etc/group").Output()
	if err != nil {
		log.Printf("Cannot exec '/usr/bin/grep %s '/etc/group': %v\n", groupname, err)
		return -1
	}
	s := strings.Trim(string(out), "\n\r ")
	comps := strings.Split(string(out), ":")
	if len(comps) < 3 {
		log.Printf("Invalid response from grep group command: %s\n", s)
		return -1
	}
	//the group id should be the third value: 'group_name:password:group_id:group_list'
	id, err := strconv.Atoi(comps[2])
	if err != nil {
		log.Printf("Invalid response from getent group command: %s\n", s)
		return -1
	}
	return id
}

func idCommand(username, arg string) int {
	//shelling out to id is used here because the os/user package
	//requires cgo, which doesn't cross-compile
	var out []byte
	var err error
	if username == "" {
		out, err = exec.Command(GetUtilPath("id"), arg).Output()
	} else {
		out, err = exec.Command(GetUtilPath("id"), arg, username).Output()
	}
	if err != nil {
		log.Fatalf("Cannot exec 'id %s %s': %v\n", arg, username, err)
	}
	s := strings.Trim(string(out), "\n\r ")
	id, err := strconv.Atoi(s)
	if err != nil {
		log.Fatalf("Unexpected UID/GID format in user record: %s\n", string(out))
	}
	return id
}

func uidGidForUser(username string) (int, int) {
	uid := idCommand(username, "-u")
	gid := idCommand(username, "-g")
	return uid, gid
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

	// update our main and then subdirectories
	changeDirectoryOwnership(siaMainDir, ownerUid, ownerGid)
	setupDirOwnership(certDir, ownerUid, ownerGid)
	setupDirOwnership(keyDir, ownerUid, ownerGid)

	//make sure the link directory exists as well
	if siaLinkDir != "" && !FileExists(siaLinkDir) {
		err := os.Symlink(siaMainDir, siaLinkDir)
		if err != nil {
			log.Printf("Unable to symlink SIA directory '%s': %v\n", siaLinkDir, err)
			return nil
		}
	}
	return nil
}

func changeDirectoryOwnership(path string, ownerUid, ownerGid int) error {
	if ownerUid == -1 && ownerGid == -1 {
		return nil
	}
	log.Printf("setting %s directory ownership set to %d/%d...\n", path, ownerUid, ownerGid)
	err := os.Chown(path, ownerUid, ownerGid)
	if err != nil {
		log.Printf("unable to update ownership: error %v\n", err)
	}
	return err
}

func setupDirOwnership(siaDir string, ownerUid, ownerGid int) {
	filepath.WalkDir(siaDir, func(path string, dirEntry fs.DirEntry, err error) error {
		if err == nil {
			err = changeDirectoryOwnership(path, ownerUid, ownerGid)
		}
		return err
	})
}

func SyscallSetGid(gid int) error {
	return syscall.Setgid(gid)
}

func SyscallSetUid(uid int) error {
	return syscall.Setuid(uid)
}
