package finder

const VERSION = "0.1"

type Config struct {
	S2SPath          string `yaml:"s2s_path"`
	HttpxIpFile      string `yaml:"httpx_ips,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	HttpxCleanFile   string `yaml:"httpx_clean,omitempty"`
	DpuxFile         string `yaml:"dpux,omitempty"`
	DnsmxFile        string `yaml:"dnsmx,omitempty"`
	PortsXMLFile     string `yaml:"ports_xml,omitempty"`
	PortsSimpleFile  string `yaml:"ports_simple,omitempty"`
}

type Project struct {
	Name       string        `yaml:"name"`
	Findings   []Finding     `yaml:"findings"`
	Infos      []Information `yaml:"infos"`
	MXRecords  []MailRecord  `yaml:"mail_dns_records"`
	DNSRecords []DNSRecord   `yaml:"dns_records"`
}

type Information struct {
	Name        string   `yaml:"name"`
	Category    Category `yaml:"category"`
	Endpoints   []string `yaml:"endpoints,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
}

type MailRecord struct {
	Host        string   `yaml:"host"`
	MXRecords   []string `yaml:"mx_records"`
	SPFEntry    string   `yaml:"spf_entry,omitempty"`
	DMARCEntry  string   `yaml:"dmarc_entry,omitempty"`
	DKIMEntries []string `yaml:"dkim_entries,omitempty"`
}

type DNSRecord struct {
	Host          string   `yaml:"host"`
	IPv4Addresses []string `yaml:"ipv4"`
	IPv6Addresses []string `yaml:"ipv6,omitempty"`
	WhoisInfo     string   `yaml:"whois,omitempty"`
}

type ServiceRecord struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
	Info     string `yaml:"protocol,omitempty"`
}

type Finding struct {
	Name         string   `yaml:"name"`
	Category     Category `yaml:"category"`
	Severity     string   `yaml:"severity,omitempty"`
	Endpoints    []string `yaml:"endpoints,omitempty"`
	Description  string   `yaml:"description,omitempty"`
	Tags         []string `yaml:"tags,omitempty"`
	Reproduction string   `yaml:"reproduction,omitempty"`
}

type Category int

const (
	All Category = iota
	Email
	DNS
	Domains
	Services
	Certificates
	OldSoftware
	Dorks
	OSINT
)

var CategoryStringMap = map[string]Category{
	"All":          All,
	"Email":        Email,
	"DNS":          DNS,
	"Domains":      Domains,
	"Services":     Services,
	"Certificates": Certificates,
	"OldSoftware":  OldSoftware,
	"Dorks":        Dorks,
	"OSINT":        OSINT,
}

type Finder struct {
	options *Options
}
