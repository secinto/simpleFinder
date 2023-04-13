package finder

const VERSION = "0.1"

type Config struct {
	S2SPath          string `yaml:"s2s_path"`
	HttpxIpFile      string `yaml:"httpx_ips,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	DnsmxFile        string `yaml:"dnsmx,omitempty"`
}

type Project struct {
	Name       string          `yaml:"name"`
	Findings   []Finding       `yaml:"findings"`
	Infos      []Information   `yaml:"infos"`
	MXRecords  []MailDNSRecord `yaml:"mail_dns_records"`
	DNSRecords []DNSRecord     `yaml:"dns_records"`
}

type Information struct {
	Name        string   `yaml:"name"`
	Category    Category `yaml:"category"`
	Endpoints   []string `yaml:"endpoints,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
}

type MailDNSRecord struct {
	Host        string   `yaml:"host"`
	Records     []string `yaml:"records"`
	SPFEntry    string   `yaml:"spf_entry,omitempty"`
	DMARCEntry  string   `yaml:"dmarc_entry,omitempty"`
	DKIMEntries []string `yaml:"dkim_entries,omitempty"`
}

type DNSRecord struct {
	Host         string
	IPv4Adresses []string
	IPv6Adresses []string
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
