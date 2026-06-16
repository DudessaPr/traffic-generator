package config

import (
	"fmt"
	"net"
)

// Validate checks Config for required fields and coherent values.
func Validate(cfg *Config) error {
	// Interface is required unless target_ip will resolve it automatically.
	if cfg.Interface == "" && len(cfg.Interfaces) == 0 && cfg.TargetIP == "" {
		return fmt.Errorf("interface (or target_ip) is required")
	}
	if len(cfg.PcapFiles) == 0 {
		return fmt.Errorf("at least one pcap_file is required")
	}
	for i, f := range cfg.PcapFiles {
		if f.Path == "" {
			return fmt.Errorf("pcap_files[%d].path is empty", i)
		}
	}
	if err := validateIPList(cfg.Mutations.SrcIPPool); err != nil {
		return fmt.Errorf("mutations.src_ip_pool: %w", err)
	}
	if err := validateIPList(cfg.Mutations.DstIPPool); err != nil {
		return fmt.Errorf("mutations.dst_ip_pool: %w", err)
	}
	if cfg.Mutations.SrcIP != "" && net.ParseIP(cfg.Mutations.SrcIP) == nil {
		return fmt.Errorf("mutations.src_ip: invalid IP %q", cfg.Mutations.SrcIP)
	}
	if cfg.Mutations.DstIP != "" && net.ParseIP(cfg.Mutations.DstIP) == nil {
		return fmt.Errorf("mutations.dst_ip: invalid IP %q", cfg.Mutations.DstIP)
	}
	if cfg.Mutations.DstMAC != "" {
		if _, err := net.ParseMAC(cfg.Mutations.DstMAC); err != nil {
			return fmt.Errorf("mutations.dst_mac: invalid MAC %q", cfg.Mutations.DstMAC)
		}
	}
	if cfg.Mutations.SrcPortMax > 0 && cfg.Mutations.SrcPortMax < cfg.Mutations.SrcPortMin {
		return fmt.Errorf("mutations.src_port_max must be >= src_port_min")
	}
	if cfg.Mutations.IPPoolLimit < 0 {
		return fmt.Errorf("mutations.ip_pool_limit must be >= 0")
	}
	switch cfg.Replay.Mode {
	case "", "sequential", "parallel", "burst", "pcap":
	default:
		return fmt.Errorf("replay.mode must be one of: sequential, parallel, burst, pcap")
	}
	if cfg.Replay.Speed < 0 {
		return fmt.Errorf("replay.speed must be >= 0 (0 = burst)")
	}
	if cfg.Replay.Workers < 0 {
		return fmt.Errorf("replay.workers must be >= 0")
	}
	if cfg.Replay.CPS < 0 {
		return fmt.Errorf("replay.cps must be >= 0")
	}
	if cfg.Replay.Multiplier < 0 {
		return fmt.Errorf("replay.multiplier must be >= 0")
	}
	if cfg.Replay.BatchSize < 0 || cfg.Replay.BatchSize > 256 {
		return fmt.Errorf("replay.batch_size must be between 0 and 256")
	}
	switch cfg.Sender {
	case "", "pcap", "raw":
	default:
		return fmt.Errorf("sender must be one of: pcap, raw")
	}
	return nil
}

func validateIPList(list []string) error {
	for _, s := range list {
		if net.ParseIP(s) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid IP or CIDR %q", s)
		}
	}
	return nil
}
