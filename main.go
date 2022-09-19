package main

import (
	"fmt"
	"os"
)

func main() {
	cmd := parseOptions()
	err := cmd.execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
