package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "tgen",
	Short: "PCAP-based network traffic generator",
	Long: `tgen replays network sessions from PCAP files onto a live interface.

It supports timing-accurate replay, L3/L4 field mutation with session
consistency, parallel and burst modes, and configurable session filtering.

Usage examples:
  tgen run -i eth0 capture.pcap
  tgen run -i eth0 --src-ip 10.0.0.1 --speed 2.0 capture.pcap
  tgen run -c config.yaml
  tgen inspect capture.pcap
  tgen sessions --min-duration 1s --proto tcp capture.pcap`,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "YAML config file")
}

func execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
