package finder

import (
	"github.com/antchfx/jsonquery"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
)

var (
	log       = NewLogger()
	appConfig Config
)

const VERSION = "0.1"

type Config struct {
	S2SPath            string `yaml:"s2s_path,omitempty"`
	ProjectName        string `yaml:"project_name,omitempty"`
	DomainName         string
	ProjectPath        string `yaml:"project_path,omitempty"`
	ResponsesFolder    string `yaml:"responses_folder,omitempty"`
	ReconFolder        string `yaml:"recon_folder,omitempty"`
	ArchiveFolder      string `yaml:"archive_folder,omitempty"`
	FindingsFolder     string `yaml:"findings_folder,omitempty"`
	HttpxIpFile        string `yaml:"httpx_ips,omitempty"`
	HttpxDomainsFile   string `yaml:"httpx_domains,omitempty"`
	DomainsFile        string `yaml:"domains_file,omitempty"`
	DpuxFile           string `yaml:"dpux_file,omitempty"`
	UniqueIpPortsFile  string `yaml:"unique_ip_ports_file,omitempty"`
	DomainsCleanedFile string `yaml:"domains_cleaned_file,omitempty"`
}

type Finder struct {
	options *Options
}

func NewFinder(options *Options) (*Finder, error) {
	pusher := &Finder{options: options}
	initialize(options.ConfigFile)
	return pusher, nil
}

func (p *Finder) Find() error {
	log.Infof("Getting findings from domains of project %s", p.options.Project)
	FindInDomains()
	return nil
}

func initialize(configLocation string) {
	appConfig = loadConfigFrom(configLocation)
}

func loadConfigFrom(location string) Config {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		path, err := os.Getwd()
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}

		yamlFile, err = os.ReadFile(path + "\\config.yaml")
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return config
}

func FindInDomains() {
	domainsJson := appConfig.HttpxDomainsFile
	input := GetDocumentFromFile(domainsJson)
	getInterestingURLs(input)
}

func FindInIPS() {
	domainsJson := appConfig.HttpxDomainsFile
	input := GetDocumentFromFile(domainsJson)
	getInterestingURLs(input)
}

func getInterestingURLs(input *jsonquery.Node) {

	idorPages := GetTitlePagesByQuery(input, []string{"'Index of', 'Setup Configuration'"})
	phpPages := GetTechPages(input, []string{"'PHP'"})
	selfSignedPages := GetSelfSignedPages(input)
	port80Pages := GetPort80Pages(input)
	webserverTypes := GetWebserverTypes(input)

	// Interesting titles
	WriteToTextFileInProject(appConfig.FindingsFolder+"/idor.txt", strings.Join(idorPages[:], "\n"))
	// Interesting tech
	WriteToTextFileInProject(appConfig.FindingsFolder+"/idor.txt", strings.Join(phpPages[:], "\n"))
	// Interesting security
	WriteToTextFileInProject(appConfig.FindingsFolder+"/idor.txt", strings.Join(selfSignedPages[:], "\n"))
	// Interesting protocol
	WriteToTextFileInProject(appConfig.FindingsFolder+"/idor.txt", strings.Join(port80Pages[:], "\n"))
	// All types of web servers encountered
	WriteToTextFileInProject(appConfig.FindingsFolder+"/idor.txt", strings.Join(webserverTypes[:], "\n"))

}
