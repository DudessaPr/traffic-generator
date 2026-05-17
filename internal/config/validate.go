package config

import (
	"fmt"
	"net"
)

// Validate checks Config for required fields and coherent values.
func Validate(cfg *Config) error {
	if cfg.Interface == "" {
		return fmt.Errorf("interface is required")
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
	if cfg.Mutations.SrcPortMax > 0 && cfg.Mutations.SrcPortMax < cfg.Mutations.SrcPortMin {
		return fmt.Errorf("mutations.src_port_max must be >= src_port_min")
	}
	switch cfg.Replay.Mode {
	case "", "sequential", "parallel", "burst":
	default:
		return fmt.Errorf("replay.mode must be one of: sequential, parallel, burst")
	}
	if cfg.Replay.Speed < 0 {
		return fmt.Errorf("replay.speed must be >= 0 (0 = burst)")
	}
	if cfg.Replay.Workers < 0 {
		return fmt.Errorf("replay.workers must be >= 0")
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
