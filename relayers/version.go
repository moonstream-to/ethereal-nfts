package main

import (
	"fmt"
	"os"
)

func RelayersVersion() string {
	version, err := os.ReadFile("version.txt")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return string(version)
}
