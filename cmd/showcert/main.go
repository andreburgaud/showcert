package main

import (
	"fmt"
	"os"

	"showcert/internal/cli"
)

func main() {
	cmd := cli.ParseOptions()
	err := cmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
