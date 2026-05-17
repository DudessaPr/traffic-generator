package main

import (
	"fmt"

	"tgen/internal/config"
	pcapreader "tgen/internal/pcap"
	"tgen/internal/session"

	"github.com/spf13/cobra"
)

var sessionsFlags struct {
	minDuration string
	maxDuration string
	startAfter  string
	startBefore string
	protos      []string
	verbose     bool
}

var sessionsCmd = &cobra.Command{
	Use:   "sessions [flags] <pcap files...>",
	Short: "List and filter sessions extracted from PCAP files",
	Long: `List every reconstructed L4 session from the given PCAP files.
Use filter flags to select sessions by duration or capture timestamp.

This is especially useful when preparing a targeted replay: identify the
session keys you care about, then pass them as mutation rules in a config file.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runSessions,
}

func init() {
	f := sessionsCmd.Flags()
	f.StringVar(&sessionsFlags.minDuration, "min-duration", "", "only show sessions longer than this (e.g. 1s)")
	f.StringVar(&sessionsFlags.maxDuration, "max-duration", "", "only show sessions shorter than this (e.g. 60s)")
	f.StringVar(&sessionsFlags.startAfter, "start-after", "", "only show sessions starting after this time (RFC 3339)")
	f.StringVar(&sessionsFlags.startBefore, "start-before", "", "only show sessions starting before this time (RFC 3339)")
	f.StringSliceVar(&sessionsFlags.protos, "proto", nil, "filter by protocol (tcp,udp,icmp)")
	f.BoolVarP(&sessionsFlags.verbose, "verbose", "v", false, "show per-session packet and byte counts")
	rootCmd.AddCommand(sessionsCmd)
}

func runSessions(_ *cobra.Command, args []string) error {
	fc := config.FilterConfig{
		MinDuration: sessionsFlags.minDuration,
		MaxDuration: sessionsFlags.maxDuration,
		StartAfter:  sessionsFlags.startAfter,
		StartBefore: sessionsFlags.startBefore,
		Protocols:   sessionsFlags.protos,
	}
	filter, err := parseFilter(fc)
	if err != nil {
		return err
	}

	for _, path := range args {
		sessions, err := pcapreader.ReadSessions(path)
		if err != nil {
			return err
		}
		matched := filter.Apply(sessions)
		fmt.Printf("# %s  (%d/%d sessions match)\n", path, len(matched), len(sessions))

		if sessionsFlags.verbose {
			fmt.Printf("%-50s %-8s %-12s %-12s %-10s\n",
				"flow", "proto", "pkts", "bytes", "duration")
			fmt.Printf("%s\n", repeatChar('-', 100))
		} else {
			fmt.Printf("%-50s %-8s %-10s\n", "flow", "proto", "duration")
			fmt.Printf("%s\n", repeatChar('-', 72))
		}

		for _, s := range matched {
			protoStr := protoLabel(s.Proto)
			if sessionsFlags.verbose {
				fmt.Printf("%-50s %-8s %-12d %-12d %s\n",
					s.Key.String(), protoStr, s.PacketCount(), s.ByteCount(), fmtDuration(s.Duration()))
			} else {
				fmt.Printf("%-50s %-8s %s\n",
					s.Key.String(), protoStr, fmtDuration(s.Duration()))
			}
		}
		fmt.Println()
	}
	return nil
}

func protoLabel(proto uint8) string {
	// Use the shared ProtoName table; unknown protocols fall back to proto<N>
	// so the label matches the string used by the session filter.
	if name, ok := session.ProtoName[proto]; ok {
		return name
	}
	return fmt.Sprintf("proto%d", proto)
}

func fmtDuration(d interface{ String() string }) string {
	return d.String()
}

func repeatChar(c rune, n int) string {
	out := make([]rune, n)
	for i := range out {
		out[i] = c
	}
	return string(out)
}
