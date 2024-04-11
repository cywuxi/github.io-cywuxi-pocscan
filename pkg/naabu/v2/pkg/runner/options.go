package runner

import (
	"os"

	"github.com/projectdiscovery/fileutil"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

// Options contains the configuration options for tuning
// the port enumeration process.
// nolint:maligned // just an option structure
type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	NoColor        bool // No-Color disables the colored output
	JSON           bool // JSON specifies whether to use json for output format or text file
	Silent         bool // Silent suppresses any extra text and only writes found host:port to screen
	Stdin          bool // Stdin specifies whether stdin input was given to the process
	Verify         bool // Verify is used to check if the ports found were valid using CONNECT method
	Version        bool // Version specifies if we should just show version and exit
	Ping           bool // Ping uses ping probes to discover fastest active host and discover dead hosts
	Debug          bool // Prints out debug information
	ExcludeCDN     bool // Excludes ip of knows CDN ranges for full port scan
	Nmap           bool // Invoke nmap detailed scan on results
	InterfacesList bool // InterfacesList show interfaces list

	Retries           int                           // Retries is the number of retries for the port
	Rate              int                           // Rate is the rate of port scan requests
	Timeout           int                           // Timeout is the seconds to wait for ports to respond
	WarmUpTime        int                           // WarmUpTime between scan phases
	Host              goflags.NormalizedStringSlice // Host is the single host or comma-separated list of hosts to find ports for
	HostsFile         string                        // HostsFile is the file containing list of hosts to find port for
	Output            string                        // Output is the file to write found ports to.
	Ports             string                        // Ports is the ports to use for enumeration
	PortsFile         string                        // PortsFile is the file containing ports to use for enumeration
	ExcludePorts      string                        // ExcludePorts is the list of ports to exclude from enumeration
	ExcludeIps        string                        // Ips or cidr to be excluded from the scan
	ExcludeIpsFile    string                        // File containing Ips or cidr to exclude from the scan
	TopPorts          string                        // Tops ports to scan
	SourceIP          string                        // SourceIP to use in TCP packets
	Interface         string                        // Interface to use for TCP packets
	ConfigFile        string                        // Config file contains a scan configuration
	NmapCLI           string                        // Nmap command (has priority over config file)
	Threads           int                           // Internal worker threads
	EnableProgressBar bool                          // Enable progress bar
	ScanAllIPS        bool                          // Scan all the ips
	ScanType          string                        // Scan Type
	Proxy             string                        // Socks5 proxy
	Resolvers         string                        // Resolvers (comma separated or file)
	baseResolvers     []string
	OnResult          OnResultCallback // OnResult callback
	CSV               bool
	StatsInterval     int // StatsInterval is the number of seconds to display stats after
	Resume            bool
	ResumeCfg         *ResumeCfg
	Stream            bool
	Passive           bool
	//
	CeyeApi    string
	CeyeDomain string
	NoPOC      bool
}

// OnResultCallback (hostname, ip, ports)
type OnResultCallback func(string, string, []int)

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`这是一个用Go编写的端口漏洞扫描工具`)

	flagSet.CreateGroup("input", "Input",
		flagSet.NormalizedStringSliceVarP(&options.Host, "host", "", []string{}, "要扫描端口的主机（逗号分隔）"),
		flagSet.StringVarP(&options.HostsFile, "l", "list", "", "要扫描端口的主机列表（文件）"),
		flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "要从扫描中排除的主机（逗号分隔）"),
		flagSet.StringVarP(&options.ExcludeIpsFile, "ef", "exclude-file", "", "要从扫描中排除的主机列表（文件）"),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "要扫描的端口，如(80,443, 100-200"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "要扫描的顶部端口（默认值为100）"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "要从扫描中排除的端口（逗号分隔）"),
		flagSet.StringVarP(&options.PortsFile, "pf", "ports-file", "", "要从扫描中排除的端口列表（文件)"),
		flagSet.BoolVarP(&options.ExcludeCDN, "ec", "exclude-cdn", false, "跳过对 CDN 的全端口扫描（只检查 80、443）"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "一般内部工作线程"),
		flagSet.IntVar(&options.Rate, "rate", DefaultRateSynScan, "每秒发送的数据包数"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "将输出写入文件（可选）"),
		flagSet.BoolVar(&options.JSON, "json", false, "以JSON格式输出"),
		flagSet.BoolVar(&options.CSV, "csv", false, "以csv格式输出"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&options.CeyeApi, "ceyeapi", "", "ceye.io api key"),
		flagSet.StringVar(&options.CeyeDomain, "ceyedomain", "", "ceye.io subdomain"),
		flagSet.BoolVar(&options.NoPOC, "np", false, "跳过POC检查"),
		flagSet.BoolVarP(&options.ScanAllIPS, "sa", "scan-all-ips", false, "扫描DNS记录"),
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", SynScan, "端口扫描类型（SYN/CONNECT）"),
		flagSet.StringVar(&options.SourceIP, "source-ip", "", "source ip"),
		flagSet.BoolVarP(&options.InterfacesList, "il", "interface-list", false, "列出可用接口和公共ip"),
		flagSet.StringVarP(&options.Interface, "i", "interface", "", "用于端口扫描的网络接口"),
		flagSet.BoolVar(&options.Nmap, "nmap", false, "对目标调用nmap扫描（必须安装nmap）-不推荐"),
		flagSet.StringVar(&options.NmapCLI, "nmap-cli", "", "要在找到的结果上运行的nmap命令（例如：-nmap cli'nmap-sV'）"),
		flagSet.StringVar(&options.Resolvers, "r", "", "自定义dns解析列表（逗号分隔或与文件分隔）"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "socks5 proxy"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "端口扫描的重试次数"),
		flagSet.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "超时前等待的毫秒"),
		flagSet.IntVar(&options.WarmUpTime, "warm-up-time", 2, "扫描阶段之间的时间（秒）"),
		flagSet.BoolVar(&options.Ping, "ping", false, "ping"),
		flagSet.BoolVar(&options.Verify, "verify", false, "使用TCP验证再次验证端口"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "显示调试信息"),
		flagSet.BoolVarP(&options.Verbose, "v", "verbose", false, "显示详细输出"),
		flagSet.BoolVarP(&options.NoColor, "nc", "no-color", false, "禁用输出中的颜色"),
		flagSet.BoolVar(&options.Silent, "silent", false, "仅在输出中显示结果"),
		flagSet.BoolVar(&options.EnableProgressBar, "stats", false, "显示正在运行的扫描的统计信息"),
		flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", DefautStatsInterval, "显示统计信息更新之间等待的秒数"),
	)

	_ = flagSet.Parse()

	// Check if stdin pipe was given
	options.Stdin = fileutil.HasStdin()

	// Read the inputs and configure the logging
	options.configureOutput()
	options.ResumeCfg = NewResumeCfg()
	if options.ShouldLoadResume() {
		if err := options.ResumeCfg.ConfigureResume(); err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
	}
	// Show the user the banner
	//showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Show network configuration and exit if the user requested it
	if options.InterfacesList {
		err := showNetworkInterfaces()
		if err != nil {
			gologger.Error().Msgf("Could not get network interfaces: %s\n", err)
		}
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err := options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	showNetworkCapabilities(options)

	return options
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFilePath())
}
