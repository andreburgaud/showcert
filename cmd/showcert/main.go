package main

import (
	"os"

	"showcert/internal/cli"
)

func main() {
	cmd := cli.ParseOptions()
	err := cmd.Execute()
	if err != nil {
		cmd.PrintError(err)
		os.Exit(1)
	}
}
