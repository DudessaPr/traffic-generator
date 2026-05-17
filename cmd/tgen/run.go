package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"tgen/internal/config"
	"tgen/internal/metrics"
	"tgen/internal/mutation"
	pcapreader "tgen/internal/pcap"
	"tgen/internal/replay"
	"tgen/internal/sender"
	"tgen/internal/session"
)

var runFlags struct {
	iface      string
	speed      float64
	mode       string
	loop       bool
	loopCount  int
	workers    int
	srcIP      string
	dstIP      string
	srcIPPool  []string
	dstIPPool  []string
	srcPortMin uint16
	srcPortMax uint16
	dstPort    uint16
	// L3 header mutations
	ttl  uint8
	dscp uint8
	// TCP header mutations
	tcpSetFlags   string
	tcpClearFlags string
	tcpWindow     uint16
	// filter flags
	minDuration string
	maxDuration string
	startAfter  string
	startBefore string
	protos      []string
}

var runCmd = &cobra.Command{
	Use:   "run [flags] <pcap files...>",
	Short: "Replay PCAP sessions onto a network interface",
	Args:  cobra.ArbitraryArgs,
	RunE:  runReplay,
}

func init() {
	f := runCmd.Flags()
	f.StringVarP(&runFlags.iface, "interface", "i", "", "network interface to send on (required)")
	f.Float64VarP(&runFlags.speed, "speed", "s", 1.0, "replay speed multiplier (0=burst, 1=real-time, 2=2×)")
	f.StringVarP(&runFlags.mode, "mode", "m", "sequential", "sequential|parallel|burst")
	f.BoolVarP(&runFlags.loop, "loop", "l", false, "replay indefinitely")
	f.IntVar(&runFlags.loopCount, "loop-count", 0, "number of replay passes (0=once)")
	f.IntVar(&runFlags.workers, "workers", 4, "goroutine count for parallel mode")
	f.StringVar(&runFlags.srcIP, "src-ip", "", "override source IP for all sessions")
	f.StringVar(&runFlags.dstIP, "dst-ip", "", "override destination IP for all sessions")
	f.StringSliceVar(&runFlags.srcIPPool, "src-ip-pool", nil, "source IP pool: random IP per session (CIDR or plain IP, repeatable)")
	f.StringSliceVar(&runFlags.dstIPPool, "dst-ip-pool", nil, "destination IP pool: random IP per session (CIDR or plain IP, repeatable)")
	f.Uint16Var(&runFlags.srcPortMin, "src-port-min", 0, "randomise source port from this value")
	f.Uint16Var(&runFlags.srcPortMax, "src-port-max", 0, "randomise source port up to this value")
	f.Uint16Var(&runFlags.dstPort, "dst-port", 0, "override destination port for all sessions")
	f.Uint8Var(&runFlags.ttl, "ttl", 0, "override TTL (IPv4) / HopLimit (IPv6); 0=keep original")
	f.Uint8Var(&runFlags.dscp, "dscp", 0, "override DSCP (0–63); 0=keep original")
	f.StringVar(&runFlags.tcpSetFlags, "tcp-set-flags", "", "TCP flags to force on, comma-separated: SYN,ACK,FIN,RST,PSH,URG")
	f.StringVar(&runFlags.tcpClearFlags, "tcp-clear-flags", "", "TCP flags to force off, comma-separated: SYN,ACK,FIN,RST,PSH,URG")
	f.Uint16Var(&runFlags.tcpWindow, "tcp-window", 0, "override TCP window size; 0=keep original")
	f.StringVar(&runFlags.minDuration, "min-duration", "", "skip sessions shorter than this (e.g. 500ms)")
	f.StringVar(&runFlags.maxDuration, "max-duration", "", "skip sessions longer than this (e.g. 30s)")
	f.StringVar(&runFlags.startAfter, "start-after", "", "skip sessions that start before this time (RFC 3339)")
	f.StringVar(&runFlags.startBefore, "start-before", "", "skip sessions that start after this time (RFC 3339)")
	f.StringSliceVar(&runFlags.protos, "proto", nil, "include only these protocols (tcp,udp,icmp)")
	rootCmd.AddCommand(runCmd)
}

func runReplay(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(args)
	if err != nil {
		return err
	}
	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	filter, err := parseFilter(cfg.Filter)
	if err != nil {
		return fmt.Errorf("filter: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Loading sessions from %d PCAP file(s)…\n", len(cfg.PcapFiles))
	var allSessions []*session.Session
	for _, src := range cfg.PcapFiles {
		sessions, err := pcapreader.ReadSessions(src.Path)
		if err != nil {
			return err
		}
		allSessions = append(allSessions, sessions...)
	}

	allSessions = filter.Apply(allSessions)
	fmt.Fprintf(os.Stderr, "Replaying %d sessions on %s (mode=%s speed=%.1f)…\n",
		len(allSessions), cfg.Interface, cfg.Replay.Mode, cfg.Replay.Speed)

	mut, err := mutation.New(cfg.Mutations)
	if err != nil {
		return fmt.Errorf("mutator: %w", err)
	}

	snd, err := sender.New(cfg.Interface)
	if err != nil {
		return err
	}
	defer snd.Close()

	interval, err := time.ParseDuration(cfg.Metrics.ReportInterval)
	if err != nil {
		interval = time.Second
	}
	mc, err := metrics.New(interval, cfg.Metrics.Output)
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	done := make(chan struct{})
	if cfg.Metrics.Enabled {
		go func() {
			mc.Run(done)
		}()
	}

	rp := replay.New(cfg.Replay, mut, snd, mc)
	err = rp.Run(ctx, allSessions)

	close(done)

	snap := mc.Snapshot()
	fmt.Fprintf(os.Stderr,
		"\nDone. packets=%d bytes=%d errors=%d sessions=%d elapsed=%.1fs\n",
		snap.PacketsSent, snap.BytesSent, snap.Errors, snap.SessionsDone, snap.ElapsedSec,
	)
	return err
}

// buildConfig produces a Config from CLI flags, merging a file if --config is set.
func buildConfig(args []string) (*config.Config, error) {
	if cfgFile != "" {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return nil, err
		}
		// CLI flags override config file fields when they are explicitly set.
		if runFlags.iface != "" {
			cfg.Interface = runFlags.iface
		}
		return cfg, nil
	}

	if runFlags.iface == "" {
		return nil, fmt.Errorf("--interface is required when no config file is provided")
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one PCAP file is required")
	}

	cfg := config.Default()
	cfg.Interface = runFlags.iface
	for _, p := range args {
		cfg.PcapFiles = append(cfg.PcapFiles, config.PcapSource{Path: p})
	}
	cfg.Replay = config.ReplayConfig{
		Mode:      runFlags.mode,
		Speed:     runFlags.speed,
		Loop:      runFlags.loop,
		LoopCount: runFlags.loopCount,
		Workers:   runFlags.workers,
	}
	cfg.Mutations = config.MutationConfig{
		PreserveSessions: true,
		SrcIP:            runFlags.srcIP,
		DstIP:            runFlags.dstIP,
		SrcIPPool:        runFlags.srcIPPool,
		DstIPPool:        runFlags.dstIPPool,
		SrcPortMin:       runFlags.srcPortMin,
		SrcPortMax:       runFlags.srcPortMax,
		DstPort:          runFlags.dstPort,
		TTL:              runFlags.ttl,
		DSCP:             runFlags.dscp,
		TCPSetFlags:      runFlags.tcpSetFlags,
		TCPClearFlags:    runFlags.tcpClearFlags,
		TCPWindow:        runFlags.tcpWindow,
	}
	cfg.Filter = config.FilterConfig{
		MinDuration: runFlags.minDuration,
		MaxDuration: runFlags.maxDuration,
		StartAfter:  runFlags.startAfter,
		StartBefore: runFlags.startBefore,
		Protocols:   runFlags.protos,
	}
	return cfg, nil
}

// parseFilter converts the string-based FilterConfig into a typed session.Filter.
func parseFilter(fc config.FilterConfig) (*session.Filter, error) {
	f := &session.Filter{}
	var err error

	if fc.MinDuration != "" {
		if f.MinDuration, err = time.ParseDuration(fc.MinDuration); err != nil {
			return nil, fmt.Errorf("min_duration %q: %w", fc.MinDuration, err)
		}
	}
	if fc.MaxDuration != "" {
		if f.MaxDuration, err = time.ParseDuration(fc.MaxDuration); err != nil {
			return nil, fmt.Errorf("max_duration %q: %w", fc.MaxDuration, err)
		}
	}
	if fc.StartAfter != "" {
		if f.StartAfter, err = time.Parse(time.RFC3339, fc.StartAfter); err != nil {
			return nil, fmt.Errorf("start_after %q: %w", fc.StartAfter, err)
		}
	}
	if fc.StartBefore != "" {
		if f.StartBefore, err = time.Parse(time.RFC3339, fc.StartBefore); err != nil {
			return nil, fmt.Errorf("start_before %q: %w", fc.StartBefore, err)
		}
	}
	if len(fc.Protocols) > 0 {
		f.Protocols = make(map[string]bool, len(fc.Protocols))
		for _, p := range fc.Protocols {
			f.Protocols[p] = true
		}
	}
	return f, nil
}
