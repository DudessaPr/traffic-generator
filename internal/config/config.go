package config

// Config is the root configuration for tgen.
type Config struct {
	Interface string         `yaml:"interface"`
	PcapFiles []PcapSource   `yaml:"pcap_files"`
	Mutations MutationConfig `yaml:"mutations"`
	Replay    ReplayConfig   `yaml:"replay"`
	Filter    FilterConfig   `yaml:"filter"`
	Metrics   MetricsConfig  `yaml:"metrics"`
}

// PcapSource describes one PCAP input file.
type PcapSource struct {
	Path string `yaml:"path"`
}

// MutationConfig controls L3/L4 field rewriting.
// Rule-based mutations take priority over global ones.
type MutationConfig struct {
	PreserveSessions bool           `yaml:"preserve_sessions"`
	SrcIP            string         `yaml:"src_ip"`
	DstIP            string         `yaml:"dst_ip"`
	SrcIPPool        []string       `yaml:"src_ip_pool"`
	DstIPPool        []string       `yaml:"dst_ip_pool"`
	SrcPortMin       uint16         `yaml:"src_port_min"`
	SrcPortMax       uint16         `yaml:"src_port_max"`
	DstPort          uint16         `yaml:"dst_port"`
	Rules            []MutationRule `yaml:"rules"`
}

// MutationRule matches a flow and provides replacement values.
type MutationRule struct {
	Match   MatchCondition `yaml:"match"`
	Replace ReplaceValues  `yaml:"replace"`
}

// MatchCondition selects sessions by L3/L4 attributes.
// Empty fields match any value. IP fields accept CIDR notation.
type MatchCondition struct {
	SrcIP   string `yaml:"src_ip"`
	DstIP   string `yaml:"dst_ip"`
	SrcPort uint16 `yaml:"src_port"`
	DstPort uint16 `yaml:"dst_port"`
	Proto   string `yaml:"proto"` // tcp, udp, icmp
}

// ReplaceValues holds new field values. Zero values mean "keep original".
type ReplaceValues struct {
	SrcIP   string `yaml:"src_ip"`
	DstIP   string `yaml:"dst_ip"`
	SrcPort uint16 `yaml:"src_port"`
	DstPort uint16 `yaml:"dst_port"`
}

// ReplayConfig controls timing and concurrency of the replay engine.
type ReplayConfig struct {
	// Mode is one of: sequential, parallel, burst.
	Mode      string  `yaml:"mode"`
	Speed     float64 `yaml:"speed"`      // 1.0 = real-time, 2.0 = 2× faster, 0 = burst
	Loop      bool    `yaml:"loop"`       // repeat indefinitely
	LoopCount int     `yaml:"loop_count"` // 0 means once; Loop overrides this
	Workers   int     `yaml:"workers"`    // goroutine count for parallel mode
}

// FilterConfig selects which sessions to include in replay (advanced feature).
// Duration strings use Go's time.ParseDuration format (e.g. "500ms", "2s", "1m").
// Timestamps use RFC 3339 format (e.g. "2024-01-15T08:00:00Z").
type FilterConfig struct {
	MinDuration string   `yaml:"min_duration"`
	MaxDuration string   `yaml:"max_duration"`
	StartAfter  string   `yaml:"start_after"`
	StartBefore string   `yaml:"start_before"`
	Protocols   []string `yaml:"protocols"` // tcp, udp, icmp
}

// MetricsConfig controls stats reporting.
type MetricsConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ReportInterval string `yaml:"report_interval"` // e.g. "1s"
	Output         string `yaml:"output"`          // stdout | stderr | <file path>
}
