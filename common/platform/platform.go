package platform // import "github.com/xtls/xray-core/common/platform"

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	ConfigLocation  = "xray.location.config"
	ConfdirLocation = "xray.location.confdir"
	AssetLocation   = "xray.location.asset"
	CertLocation    = "xray.location.cert"

	UseReadV         = "xray.buf.readv"
	UseFreedomSplice = "xray.buf.splice"
	UseVmessPadding  = "xray.vmess.padding"
	UseCone          = "xray.cone.disabled"
	UseStrictJSON    = "xray.json.strict"

	BufferSize           = "xray.ray.buffer.size"
	BrowserDialerAddress = "xray.browser.dialer"
	XUDPLog              = "xray.xudp.show"
	XUDPBaseKey          = "xray.xudp.basekey"

	TunFdKey = "xray.tun.fd"
	// TunRefuseIPv6Key, when "1", makes the tun stack reset IPv6 TCP and drop IPv6 UDP instead of
	// accepting them for an upstream that cannot carry them (mobile clients of IPv4-only nodes).
	TunRefuseIPv6Key = "xray.tun.ipv6.refuse"
	// TunMaxTCPFlowsKey caps how many TCP connections of a tun are dispatched at once; the rest wait,
	// established, for a slot (and are reset after TunFlowWaitKey seconds). Every dispatched flow of a
	// VLESS+Vision client is its own TLS session on the way out, ~180 KiB, which an iOS packet tunnel
	// (50 MiB) cannot afford a hundred of. Ports 53 (health probes to the resolver) and 5223 (Apple push,
	// one long-lived connection per device) are exempt.
	TunMaxTCPFlowsKey = "xray.tun.tcp.maxflows"
	TunFlowWaitKey    = "xray.tun.tcp.flowwait"
	// TunIdleEvictKey: when every slot of the cap is taken, the dispatched flow that has carried nothing
	// for at least this many seconds (default 5) is closed to make room, longest idle first, before a new
	// flow is made to wait. The slots would otherwise fill with the keep-alive connections a page leaves
	// behind, which servers keep for minutes, and every new flow of the device would wait and be reset.
	TunIdleEvictKey = "xray.tun.tcp.idleevict"
	// TunWindowKey overrides the per-connection window (bytes) of the stack on a plain tun: what it buffers
	// unread from the system and unacknowledged to it. The system is a hop away, so a small window costs
	// nothing in throughput; the default 256 KiB times a page's hundred connections is more than an iOS
	// packet tunnel may hold.
	TunWindowKey = "xray.tun.window"
	// TunLargeWindowKey overrides the receive window (bytes) of the stack behind a tunnel tun
	// (the wireguard outbound's). The default 1 MiB per connection is too much for a 50 MiB
	// iOS packet tunnel under parallel downloads.
	TunLargeWindowKey = "xray.tun.window.large"
)

type EnvFlag struct {
	Name    string
	AltName string
}

func NewEnvFlag(name string) EnvFlag {
	return EnvFlag{
		Name:    name,
		AltName: NormalizeEnvName(name),
	}
}

func (f EnvFlag) GetValue(defaultValue func() string) string {
	if v, found := os.LookupEnv(f.Name); found {
		return v
	}
	if len(f.AltName) > 0 {
		if v, found := os.LookupEnv(f.AltName); found {
			return v
		}
	}

	return defaultValue()
}

func (f EnvFlag) GetValueAsInt(defaultValue int) int {
	useDefaultValue := false
	s := f.GetValue(func() string {
		useDefaultValue = true
		return ""
	})
	if useDefaultValue {
		return defaultValue
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return defaultValue
	}
	return int(v)
}

func NormalizeEnvName(name string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(name)), ".", "_")
}

func GetExecutableDir() string {
	exec, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exec)
}

func GetConfigurationPath() string {
	configPath := NewEnvFlag(ConfigLocation).GetValue(GetExecutableDir)
	return filepath.Join(configPath, "config.json")
}

// GetConfDirPath reads "xray.location.confdir"
func GetConfDirPath() string {
	configPath := NewEnvFlag(ConfdirLocation).GetValue(func() string { return "" })
	return configPath
}
