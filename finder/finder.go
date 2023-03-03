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
	S2SPath          string `yaml:"s2s_path,omitempty"`
	HttpxIpFile      string `yaml:"httpx_ips,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
}

type Finder struct {
	options *Options
}

func NewFinder(options *Options) (*Finder, error) {
	finder := &Finder{options: options}
	finder.initialize(options.ConfigFile)
	return finder, nil
}

func (p *Finder) Find() error {
	if p.options.Project != "" {
		log.Infof("Getting findings from domains of project %s", p.options.Project)
		p.FindInDomains()
	} else {
		log.Info("No project specified. Exiting application")
	}
	return nil
}

func (p *Finder) initialize(configLocation string) {
	appConfig = loadConfigFrom(configLocation)
	p.options.BaseFolder = appConfig.S2SPath + "/" + p.options.Project
	appConfig.HttpxIpFile = strings.Replace(appConfig.HttpxIpFile, "{project_name}", p.options.Project, -1)
	appConfig.HttpxDomainsFile = strings.Replace(appConfig.HttpxDomainsFile, "{project_name}", p.options.Project, -1)
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

func (p *Finder) FindInDomains() {

	input := GetDocumentFromFile(p.options.BaseFolder + "/recon/" + appConfig.HttpxDomainsFile)
	p.getInterestingURLs(input)
}

func (p *Finder) FindInIPS() {
	input := GetDocumentFromFile(p.options.BaseFolder + "/recon/" + appConfig.HttpxIpFile)
	p.getInterestingURLs(input)
}

func (p *Finder) getInterestingURLs(input *jsonquery.Node) {

	idorPages := GetTitlePagesByQuery(input, []string{"'Index of', 'Setup Configuration'"})
	phpPages := GetTechPages(input, []string{"'PHP'"})
	selfSignedPages := GetSelfSignedPages(input)
	port80Pages := GetPort80Pages(input)
	webserverTypes := GetWebserverTypes(input)

	// Interesting titles
	WriteToTextFileInProject(p.options.BaseFolder+"/findings/idor.txt", strings.Join(idorPages[:], "\n"))
	// Interesting tech
	WriteToTextFileInProject(p.options.BaseFolder+"/findings/php.txt", strings.Join(phpPages[:], "\n"))
	// Interesting security
	WriteToTextFileInProject(p.options.BaseFolder+"/findings/self_signed.txt", strings.Join(selfSignedPages[:], "\n"))
	// Interesting protocol
	WriteToTextFileInProject(p.options.BaseFolder+"/findings/port_80.txt", strings.Join(port80Pages[:], "\n"))
	// All types of web servers encountered
	WriteToTextFileInProject(p.options.BaseFolder+"/findings/server_types.txt", strings.Join(webserverTypes[:], "\n"))

}
