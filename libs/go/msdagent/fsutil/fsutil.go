package fsutil

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/AthenZ/athenz/libs/go/msdagent/log"
)

func Exists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func WriteFile(content interface{}, ipFile string) error {
	file, err := json.MarshalIndent(content, "", " ")
	if err == nil {
		err = ioutil.WriteFile(ipFile, file, 0644)
		if err != nil {
			log.Printf("Failed to write file, Error: %v", err)
			return err
		}
	} else {
		log.Printf("Failed marshal struct, Error: %v", err)
		return err
	}
	return nil
}

func ReadFile(filePath string, value interface{}) error {

	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read file: %v", err)
		return err
	}

	err = json.Unmarshal(file, value)
	if err != nil {
		log.Printf("Failed to unmarshal file: %v", err)
		return err
	}
	return nil
}
