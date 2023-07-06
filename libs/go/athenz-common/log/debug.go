// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package log

import (
	"fmt"
	"io"
	"log"
)

var Debug bool
var writer io.Writer

func Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

func Errorf(format string, v ...interface{}) error {
	log.Printf(format, v...)
	return fmt.Errorf(format, v...)
}

func Print(v ...interface{}) {
	log.Print(v...)
}

func Debugf(format string, v ...interface{}) {
	if Debug {
		log.Printf(format, v...)
	}
}

func Fatalf(format string, v ...interface{}) {
	log.Fatalf(format, v...)
}

func SetOutput(w io.Writer) {
	writer = w
	log.SetOutput(w)
}

func GetWriter() io.Writer {
	return writer
}
