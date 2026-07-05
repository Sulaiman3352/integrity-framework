/*
Copyright © 2026 Sulayman Seid Ymam email@later.com
*/
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	//"github.com/sulaiman3352/integrity-framework/walia-cli/cmd"
	//"golang.org/x/sys/unix"
	//"google.golang.org/grpc"
)

var rootCmd = &cobra.Command{
	Use:   "walia-cli",
	Short: "Command line for the integrity framework",
	Long:  "This Command line tool for Walia Guard which can help to manage the daemon using the terminal",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("this just for test")
	},
}

func Execute(){
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}
