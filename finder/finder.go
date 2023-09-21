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
	project   Project
)

/*
--------------------------------------------------------------------------------

	Initialization functions for the application

-------------------------------------------------------------------------------
*/
func (p *Finder) initialize(configLocation string) {
	appConfig = loadConfigFrom(configLocation)
	if !strings.HasSuffix(appConfig.S2SPath, "/") {
		appConfig.S2SPath = appConfig.S2SPath + "/"
	}
	p.options.BaseFolder = appConfig.S2SPath + p.options.Project
	if !strings.HasSuffix(p.options.BaseFolder, "/") {
		p.options.BaseFolder = p.options.BaseFolder + "/"
	}
	appConfig.HttpxIpFile = strings.Replace(appConfig.HttpxIpFile, "{project_name}", p.options.Project, -1)
	appConfig.HttpxDomainsFile = strings.Replace(appConfig.HttpxDomainsFile, "{project_name}", p.options.Project, -1)

	project = Project{
		Name: p.options.Project,
	}
}

func loadConfigFrom(location string) Config {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		yamlFile, err = os.ReadFile(defaultSettingsLocation)
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	if &config == nil {
		config = Config{
			S2SPath:          "S://",
			HttpxIpFile:      "http_from.{project_name}.ips.output.json",
			HttpxDomainsFile: "http_from.{project_name}.domains.output.json",
			HttpxCleanFile:   "http_from.clean.output.json",
		}
	}
	return config
}

func NewFinder(options *Options) (*Finder, error) {
	finder := &Finder{options: options}
	finder.initialize(options.SettingsFile)
	return finder, nil
}

func (p *Finder) Find() error {
	if p.options.Project != "" {
		log.Infof("Getting findings for project %s", p.options.Project)
		if p.options.Hosts {
			log.Info("Performing HTTP site checks")
			p.FindInterestingAllCleaned()
		} else {
			log.Info("Performing HTTP site checks")
			p.FindInterestingAllCleaned()
		}
	} else {
		log.Info("No project specified. Exiting application")
	}
	return nil
}

/*
--------------------------------------------------------------------------------
 Public functions of the application
-------------------------------------------------------------------------------
*/

func (p *Finder) FindInterestingDomains() {

	input := GetJSONDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.HttpxDomainsFile)
	p.getInterestingURLs(input)
}

func (p *Finder) FindInterestingIPS() {
	input := GetJSONDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.HttpxIpFile)
	p.getInterestingURLs(input)
}

func (p *Finder) FindInterestingAllCleaned() {
	input := GetJSONDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.HttpxCleanFile)
	p.getInterestingURLs(input)
}

/*
--------------------------------------------------------------------------------

	Internal functions of the application

-------------------------------------------------------------------------------
*/
func (p *Finder) getInterestingURLs(input *jsonquery.Node) {

	errorPages := GetValueForQueryKey(input, "url", "title", []string{"'Error', 'Fehler', 'Exception'"})
	idorPages := GetValueForQueryKey(input, "url", "title", []string{"'Index of'", "'Setup Configuration'"})
	loginPages := GetValueForQueryKey(input, "url", "title", []string{"'Anmelden'", "'Login'", "'Anmeldung'", "'Authentication'", "'Authorization'"})
	dbManagementPages := GetValueForQueryKey(input, "url", "title", []string{"'phpMyAdmin'", "'Adminer'"})

	phpPages := GetValueForQueryKey(input, "url", "tech", []string{"'PHP'"})
	mySQLPages := GetValueForQueryKey(input, "url", "tech", []string{"'MySQL'"})
	tomcatPages := GetValueForQueryKey(input, "url", "tech", []string{"'Tomcat'"})
	javaPages := GetValueForQueryKey(input, "url", "tech", []string{"'Java'"})

	devPages := GetValueForQueryKey(input, "url", "url", []string{"'dev'"})
	port80Pages := GetValueForQueryKey(input, "url", "url", []string{"':80'"})

	selfSignedPages := GetValueForQueryBoolean(input, "url", "self_signed", true)

	webserverTypes := GetAllValuesForKey(input, "webserver")

	CreateDirectoryIfNotExists(p.options.BaseFolder + "findings/")

	// Interesting titles
	if len(errorPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/errors.txt", strings.Join(errorPages[:], "\n"))
		log.Infof("Found %d hosts with interesting error pages", len(errorPages))
	}
	if len(idorPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/idorPages.txt", strings.Join(idorPages[:], "\n"))
		log.Infof("Found %d hosts with interesting idor pages", len(idorPages))
	}
	if len(loginPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/loginPages.txt", strings.Join(loginPages[:], "\n"))
		log.Infof("Found %d hosts with interesting login pages", len(loginPages))
	}
	if len(dbManagementPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/dbManagementPages.txt", strings.Join(dbManagementPages[:], "\n"))
		log.Infof("Found %d hosts with interesting DB management pages", len(dbManagementPages))
	}
	// Interesting tech
	if len(phpPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/phpPages.txt", strings.Join(phpPages[:], "\n"))
		log.Infof("Found %d hosts with PHP pages", len(phpPages))
	}
	if len(mySQLPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/mySQLPages.txt", strings.Join(mySQLPages[:], "\n"))
		log.Infof("Found %d hosts with MySQL", len(phpPages))
	}
	if len(tomcatPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/tomcatPages.txt", strings.Join(tomcatPages[:], "\n"))
		log.Infof("Found %d hosts with Tomcat", len(tomcatPages))
	}
	if len(javaPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/javaPages.txt", strings.Join(javaPages[:], "\n"))
		log.Infof("Found %d hosts with Java", len(javaPages))
	}
	// Interesting TLS information
	if len(selfSignedPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/selfSignedPages.txt", strings.Join(selfSignedPages[:], "\n"))
		log.Infof("Found %d hosts with self signed certificates", len(selfSignedPages))
	}
	// Interesting protocol or port
	if len(port80Pages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/port80Pages.txt", strings.Join(port80Pages[:], "\n"))
		log.Infof("Found %d hosts with port 80 available", len(port80Pages))
	}
	// Interesting URL names
	if len(devPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/devPages.txt", strings.Join(devPages[:], "\n"))
		log.Infof("Found %d hosts with \"dev\" in the name of the URL", len(devPages))
	}
	// All types of web servers encountered
	if len(webserverTypes) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/server_types.txt", strings.Join(webserverTypes[:], "\n"))
		log.Infof("Found %d different web server types", len(webserverTypes))
	}
}
