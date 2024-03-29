package finder

const VERSION = "0.2.1"

type Config struct {
	ProjectsPath     string `yaml:"projects_path"`
	HttpxIpFile      string `yaml:"httpx_ips,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	HttpxCleanFile   string `yaml:"httpx_clean,omitempty"`
}

type Project struct {
	Name string `json:"name"`
}

type Finder struct {
	options *Options
}
