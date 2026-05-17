package main

import (
	"fmt"

	"github.com/spf13/cobra"
	pcapreader "tgen/internal/pcap"
	"tgen/internal/session"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <pcap files...>",
	Short: "Print statistics for one or more PCAP files",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runInspect,
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}

func runInspect(_ *cobra.Command, args []string) error {
	for _, path := range args {
		stats, err := pcapreader.Inspect(path)
		if err != nil {
			return err
		}
		sessions, err := pcapreader.ReadSessions(path)
		if err != nil {
			return err
		}
		totalPackets, totalBytes := 0, 0
		for _, s := range sessions {
			totalPackets += s.PacketCount()
			totalBytes += s.ByteCount()
		}
		fmt.Printf("File:     %s\n", stats.Path)
		fmt.Printf("Packets:  %d\n", stats.PacketCount)
		fmt.Printf("Bytes:    %d\n", stats.ByteCount)
		fmt.Printf("Sessions: %d\n", len(sessions))
		fmt.Printf("Duration: %s\n", stats.Duration)
		fmt.Printf("Start:    %s\n", stats.FirstPacket.UTC())
		fmt.Printf("End:      %s\n", stats.LastPacket.UTC())
		printProtoBreakdown(sessions)
		fmt.Println()
	}
	return nil
}

func printProtoBreakdown(sessions []*session.Session) {
	counts := map[string]int{}
	for _, s := range sessions {
		// Use the shared ProtoName table; unknown protocols fall back to proto<N>.
		name, ok := session.ProtoName[s.Proto]
		if !ok {
			name = fmt.Sprintf("proto%d", s.Proto)
		}
		counts[name]++
	}
	fmt.Printf("Protocols:")
	for name, n := range counts {
		fmt.Printf(" %s=%d", name, n)
	}
	fmt.Println()
}
