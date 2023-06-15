package finder

const VERSION = "0.1"

type Config struct {
	S2SPath          string `yaml:"s2s_path"`
	HttpxIpFile      string `yaml:"httpx_ips,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	HttpxCleanFile   string `yaml:"httpx_clean,omitempty"`
	DpuxFile         string `yaml:"dpux,omitempty"`
	DpuxCleanFile    string `yaml:"dpux_clean,omitempty"`
	DnsmxFile        string `yaml:"dnsmx,omitempty"`
}

type Project struct {
	Name string `json:"name"`
}

type Information struct {
	Name        string   `json:"name"`
	Category    Category `json:"category"`
	Endpoints   []string `json:"endpoints,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type MailRecord struct {
	Host        string   `json:"Host"`
	MXRecords   []string `json:"MXRecords"`
	SPFEntry    string   `json:"SPFEntry,omitempty"`
	DMARCEntry  string   `json:"DMARCEntry,omitempty"`
	DKIMEntries []string `json:"DKIMEntries,omitempty"`
}

type DNSRecord struct {
	Host          string   `json:"Host"`
	IPv4Addresses []string `json:"IPv4Addresses"`
	IPv6Addresses []string `json:"IPv6Addresses,omitempty"`
	WhoisInfo     string   `json:"WhoisInfo,omitempty"`
}

type ServiceRecord struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
	Info     string `yaml:"protocol,omitempty"`
}

type Finding struct {
	Name         string   `json:"name"`
	Category     Category `json:"category"`
	Severity     string   `json:"severity,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	Description  string   `json:"description,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Reproduction string   `json:"reproduction,omitempty"`
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
