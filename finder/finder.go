package finder

import (
	"encoding/json"
	"github.com/antchfx/jsonquery"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var (
	log        = NewLogger()
	appConfig  Config
	windows_os = false
	project    Project
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
	appConfig.DnsmxFile = strings.Replace(appConfig.DnsmxFile, "{project_name}", p.options.Project, -1)

	if runtime.GOOS == "windows" {
		windows_os = true
	}

	project = Project{
		Name:     p.options.Project,
		Findings: nil,
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
			DnsmxFile:        "dnsmx.{project_name}.output.json",
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
		if p.options.DNS {
			mxRecords := p.FindMailRecords()
			data, _ := json.MarshalIndent(mxRecords, "", " ")

			WriteToTextFileInProject(p.options.BaseFolder+"/findings/mailsecuritylist.json", string(data))
			log.Infof("%d Mail security records have been found", len(mxRecords))
		} else {
			p.FindInterestingDomains()
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

	input := GetDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.HttpxDomainsFile)
	p.getInterestingURLs(input)
}

func (p *Finder) FindInterestingIPS() {
	input := GetDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.HttpxIpFile)
	p.getInterestingURLs(input)
}

func (p *Finder) FindMailRecords() []MailDNSRecord {
	var mxRecords []MailDNSRecord
	input := GetDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.DnsmxFile)
	// Get MX records for the main site (the one named as the project
	//mainMXRecords := GetMXRecords(input, p.options.Project, true)
	allMXRecords := GetMXRecords(input, p.options.Project, false)
	// Check DNS entries for main domain
	/*
		if len(mainMXRecords) >= 1 {
			// Fine, we found at least one. Now check if the other information (SPF, DMARC, DKIM) is available.
			mxRecordEntries := getValuesFromNode(mainMXRecords[0], "mx")
			mxRecord := MailDNSRecord{
				Host:    p.options.Project,
				Records: mxRecordEntries,
			}
			mxRecords = append(mxRecords, mxRecord)
		} else {
			// No entry for the main site, is very unusual, maybe we used the wrong site. But if not, should be in
			// the report.
			log.Errorf("No MX entry found for main site %s", p.options.Project)
		}*/
	// Check all other entries from DNSX
	if len(allMXRecords) >= 1 {
		// Fine, we found at least one. Now check if the other information (SPF, DMARC, DKIM) is available.
		for _, mxRecordNode := range allMXRecords {
			hostEntries := getValuesFromNode(mxRecordNode, "host")
			if len(hostEntries) >= 1 {
				txtEntries := getValuesFromNode(mxRecordNode, "txt")
				dmarcEntry := getNodesFromSpecificQueryViaEquals(input, "mx", "host", "_dmarc."+hostEntries[0])
				if len(dmarcEntry) > 0 {
					log.Infof("DMARC entry for main site found.")
				}

				// Check if this is an entry for a TLD.
				// TODO: Check if only using the first entry is OK.
				if hostEntries[0] == ("_dmarc." + p.options.Project) {
					/* DMARC entry for main site */
					foundRecord := p.getRecordForHost(mxRecords, p.options.Project)
					if foundRecord.DMARCEntry == "" && len(txtEntries) > 0 {
						for _, txtEntry := range txtEntries {
							if strings.Contains(strings.ToLower(txtEntry), "dmarc") {
								foundRecord.DMARCEntry = txtEntry
							}
						}
					} else if len(txtEntries) == 0 {
						log.Infof("No TXT entries for host %s", p.options.Project)
					} else {
						log.Infof("Host %s already has dmarc entry %s", p.options.Project, foundRecord.DMARCEntry)
					}
					// Check if the host entry starts with _dmarc and is not for the TLD
				} else if strings.HasPrefix(strings.ToLower(hostEntries[0]), "_dmarc") {
					/* DMARC entry for any site */
					host := strings.Replace(hostEntries[0], "_dmarc.", "", 1)
					foundRecord := p.getRecordForHost(mxRecords, host)
					if foundRecord.DMARCEntry == "" && len(txtEntries) > 0 {
						for _, txtEntry := range txtEntries {
							if strings.Contains(strings.ToLower(txtEntry), "dmarc") {
								foundRecord.DMARCEntry = txtEntry
							}
						}
					} else if len(txtEntries) == 0 {
						log.Infof("No TXT entries for host %s", host)
					} else {
						log.Infof("Host %s already has dmarc entry %s", host, foundRecord.DMARCEntry)
					}
				} else {
					mxRecordEntries := getValuesFromNode(mxRecordNode, "mx")
					mxRecord := MailDNSRecord{
						Host:    hostEntries[0],
						Records: mxRecordEntries,
					}
					// Check if the host has an SPF entry.
					if len(txtEntries) > 0 {
						for _, txtEntry := range txtEntries {
							if strings.Contains(strings.ToLower(txtEntry), "spf") {
								mxRecord.SPFEntry = txtEntry
							}
						}
					}

					mxRecords = append(mxRecords, mxRecord)
				}

			} else {
				log.Errorf("Found records without host value. %s", mxRecordNode)
			}
		}
	}

	return mxRecords
}

func (p *Finder) FindDomainExpiryRecords() {
}
func (p *Finder) FindSubdomainTakeoverRecords() {
}

/*
--------------------------------------------------------------------------------

	Internal functions of the application

-------------------------------------------------------------------------------
*/
func (p *Finder) getInterestingURLs(input *jsonquery.Node) {

	titlePages := GetTitlePagesByQuery(input, []string{"'Index of', 'Setup Configuration'"})
	errorPages := GetTitlePagesByQuery(input, []string{"'Error', 'Fehler', 'Exception'"})
	phpPages := GetTechPages(input, []string{"'PHP'"})
	selfSignedPages := GetSelfSignedPages(input)
	port80Pages := GetPort80Pages(input)
	webserverTypes := GetWebserverTypes(input)

	CreateDirectoryIfNotExists(p.options.BaseFolder + "findings/")

	// Interesting titles
	if len(titlePages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/titles.txt", strings.Join(titlePages[:], "\n"))
		log.Infof("Found %d hosts with interesting title pages", len(titlePages))
	}
	// Interesting errors
	if len(errorPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/errors.txt", strings.Join(errorPages[:], "\n"))
		log.Infof("Found %d hosts with interesting error pages", len(errorPages))
	}
	// Interesting tech
	if len(phpPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/php.txt", strings.Join(phpPages[:], "\n"))
		log.Infof("Found %d hosts with PHP pages", len(phpPages))
	}
	// Interesting security
	if len(selfSignedPages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/self_signed.txt", strings.Join(selfSignedPages[:], "\n"))
		log.Infof("Found %d hosts with self signed certificates", len(selfSignedPages))
	}
	// Interesting protocol
	if len(port80Pages) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/port_80.txt", strings.Join(port80Pages[:], "\n"))
		log.Infof("Found %d hosts with port 80 available", len(port80Pages))
	}
	// All types of web servers encountered
	if len(webserverTypes) > 0 {
		WriteToTextFileInProject(p.options.BaseFolder+"findings/server_types.txt", strings.Join(webserverTypes[:], "\n"))
		log.Infof("Found %d different web server types", len(webserverTypes))
	}
}

func (p *Finder) executeShellCommand(command string, input []string) string {

	out, err := exec.Command(command, input...).Output()
	if err != nil {
		log.Fatalf("Executing command %s with params %s was not successful.", command, input)
	}
	return string(out)
}

func (p *Finder) getRecordForHost(records []MailDNSRecord, host string) *MailDNSRecord {
	var result *MailDNSRecord
	for _, record := range records {
		if record.Host == host {
			result = &record
		}
	}
	if result == nil {
		result = &MailDNSRecord{
			Host: host,
		}
	}
	return result
}

//func (p *Finder) getSPFEntryForHost()
