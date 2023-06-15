package finder

import (
	"encoding/json"
	"github.com/antchfx/jsonquery"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
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
	appConfig.DnsmxFile = strings.Replace(appConfig.DnsmxFile, "{project_name}", p.options.Project, -1)
	//appConfig.PortsXMLFile = strings.Replace(appConfig.PortsXMLFile, "{project_name}", p.options.Project, -1)

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
			DpuxFile:         "dpux.{project_name}.output.json",
			DpuxCleanFile:    "dpux_clean.json",
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
		if p.options.Email {
			log.Info("Performing mail checks")
			mxRecords := p.FindMailRecords()
			data, _ := json.MarshalIndent(mxRecords, "", " ")
			WriteToTextFileInProject(p.options.BaseFolder+"/findings/mailsecurity.json", string(data))
			log.Infof("%d Mail information records have been found", len(mxRecords))

		} else if p.options.DNS {
			log.Info("Performing DNS checks")
			dnsRecords := p.FindDNSRecords()
			data, _ := json.MarshalIndent(dnsRecords, "", " ")
			WriteToTextFileInProject(p.options.BaseFolder+"/findings/dns.json", string(data))
			log.Infof("%d DNS information records have been found", len(dnsRecords))
		} else if p.options.Ports {
			log.Info("Performing service checks")
			serviceRecords := p.FindServiceRecords()
			data, _ := json.MarshalIndent(serviceRecords, "", " ")
			WriteToTextFileInProject(p.options.BaseFolder+"/findings/services.json", string(data))
			log.Infof("%d Service information records have been found", len(serviceRecords))
		} else if p.options.All {
			//p.FindInterestingDomains()
			log.Info("Performing HTTP site checks")
			p.FindInterestingAllCleaned()
			log.Info("Performing mail checks")
			mxRecords := p.FindMailRecords()
			data, _ := json.MarshalIndent(mxRecords, "", " ")
			WriteToTextFileInProject(p.options.BaseFolder+"/findings/mailsecurity.json", string(data))
			log.Infof("%d Mail information records have been found", len(mxRecords))
			log.Info("Performing DNS checks")
			dnsRecords := p.FindDNSRecords()
			data, _ = json.MarshalIndent(dnsRecords, "", " ")
			WriteToTextFileInProject(p.options.BaseFolder+"/findings/dns.json", string(data))
			log.Infof("%d DNS information records have been found", len(dnsRecords))
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

func (p *Finder) FindMailRecords() []MailRecord {
	var mxRecords []MailRecord
	input := GetJSONDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.DnsmxFile)
	// Get MX records for the main site (the one named as the project
	allMXRecords := GetAllRecordsForKey(input, "mx")
	// Check all other entries from DNSX
	if len(allMXRecords) >= 1 {
		// Fine, we found at least one. Now check if the other information (SPF, DMARC, DKIM) is available.
		for _, mxRecordNode := range allMXRecords {
			hostEntries := getValuesFromNode(mxRecordNode, "host")

			if len(hostEntries) >= 1 {
				mxRecordEntries := getValuesFromNode(mxRecordNode, "mx")
				mxRecord := MailRecord{
					Host:      hostEntries[0],
					MXRecords: mxRecordEntries,
				}
				// Check if the host has an SPF entry.
				txtEntries := getValuesFromNode(mxRecordNode, "txt")
				if len(txtEntries) > 0 {
					for _, txtEntry := range txtEntries {
						if strings.Contains(strings.ToLower(txtEntry), "spf") {
							mxRecord.SPFEntry = txtEntry
						}
					}
				}
				// Check if an DMARC entry exists for the current host
				dmarcEntries := getNodesFromSpecificQueryViaEquals(input, "host", "_dmarc."+hostEntries[0])
				if len(dmarcEntries) > 0 {
					dmarcEntry := getValuesFromNode(dmarcEntries[0], "txt")
					if dmarcEntry != nil {
						mxRecord.DMARCEntry = dmarcEntry[0]
					}
				}

				dkimEntries := getAllNodesByContains(input, "host", []string{"_domainkey." + hostEntries[0]})
				if len(dkimEntries) > 0 {
					var entries []string
					for _, dkimEntry := range dkimEntries {
						dkimValue := getValuesFromNode(dkimEntry.Parent, "txt")
						if len(dkimValue) > 0 {
							entries = append(entries, strings.Join(dkimValue, ""))
						}
					}
					if len(entries) > 0 {
						mxRecord.DKIMEntries = entries
					}
				}
				if !strings.HasPrefix(hostEntries[0], "_dmarc.") && !strings.Contains(hostEntries[0], "_domainkey.") {
					mxRecords = append(mxRecords, mxRecord)
				} else {
					log.Infof("Not using DNS record for %s", hostEntries[0])
				}
			} else {
				log.Errorf("Found records without host value. %s", mxRecordNode)
			}
		}
	}

	return mxRecords
}

func (p *Finder) FindDNSRecords() []DNSRecord {
	input := GetJSONDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.DnsmxFile)
	allDNSRecords := GetAllRecordsForKey(input, "host")
	// Check all other entries from DNSX

	dnsRecords := make(map[string]DNSRecord)
	if len(allDNSRecords) >= 1 {
		for _, dnsRecordNode := range allDNSRecords {
			if entryValues, ok := dnsRecordNode.Value().(map[string]interface{}); ok {
				if len(entryValues) > 0 {
					host := entryValues["host"].(string)
					var ip4Addresses []string
					var ip6Addresses []string

					if _, exists := dnsRecords[host]; !exists {

						if entries, ok := entryValues["a"].([]interface{}); ok {
							for _, address := range entries {
								if _, ok := address.(string); ok {
									ip4Addresses = append(ip4Addresses, address.(string))
								}
							}
						} else if entry, ok := entryValues["a"].(string); ok {
							ip4Addresses = append(ip4Addresses, entry)
						}

						if entries, ok := entryValues["aaaa"].([]interface{}); ok {
							for _, address := range entries {
								if _, ok := address.(string); ok {
									ip6Addresses = append(ip6Addresses, address.(string))
								}
							}
						} else if entry, ok := entryValues["aaaa"].(string); ok {
							ip6Addresses = append(ip6Addresses, entry)
						}
					} else {
						ip4Addresses = dnsRecords[host].IPv4Addresses
						ip6Addresses = dnsRecords[host].IPv6Addresses

						if entries, ok := entryValues["a"].([]interface{}); ok {
							for _, address := range entries {
								if _, ok := address.(string); ok {
									ip4Addresses = append(ip4Addresses, address.(string))
								}
							}
						} else if entry, ok := entryValues["a"].(string); ok {
							ip4Addresses = append(ip4Addresses, entry)
						}

						if entries, ok := entryValues["a"].([]interface{}); ok {
							for _, address := range entries {
								if _, ok := address.(string); ok {
									ip6Addresses = append(ip6Addresses, address.(string))
								}
							}
						} else if entry, ok := entryValues["aaaa"].(string); ok {
							ip6Addresses = append(ip6Addresses, entry)
						}
					}
					if !strings.HasPrefix(host, "_dmarc.") && !strings.Contains(host, "_domainkey.") {

						dnsRecords[host] = DNSRecord{
							Host:          host,
							IPv4Addresses: ip4Addresses,
							IPv6Addresses: ip6Addresses,
						}
					} else {
						log.Infof("Not using host %s for dns.json", host)
					}
				}
			}
		}
	}
	//Convert map to array
	var values []DNSRecord
	for _, value := range dnsRecords {
		values = append(values, value)
	}
	return values
}

func (p *Finder) FindServiceRecords() []DNSRecord {
	var dnsRecords []DNSRecord
	input := GetJSONDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.DpuxCleanFile)
	allDNSRecords := GetAllRecordsForKey(input, "host")
	// Check all other entries from DNSX
	if len(allDNSRecords) >= 1 {
		for _, dnsRecordNode := range allDNSRecords {
			dnsRecord := p.getDNSRecordForHost(dnsRecords, dnsRecordNode.Value().(string))
			dnsRecords = append(dnsRecords, *dnsRecord)
		}
	}
	return dnsRecords
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

func (p *Finder) executeShellCommand(command string, input []string) string {

	out, err := exec.Command(command, input...).Output()
	if err != nil {
		log.Fatalf("Executing command %s with params %s was not successful.", command, input)
	}
	return string(out)
}

func (p *Finder) getMXRecordForHost(records []MailRecord, host string) *MailRecord {
	var result *MailRecord
	for _, record := range records {
		if record.Host == host {
			result = &record
		}
	}
	if result == nil {
		result = &MailRecord{
			Host: host,
		}
	}
	return result
}

func (p *Finder) getDNSRecordForHost(records []DNSRecord, host string) *DNSRecord {
	var result *DNSRecord
	for _, record := range records {
		if record.Host == host {
			result = &record
		}
	}
	if result == nil {
		result = &DNSRecord{
			Host: host,
		}
	}
	return result
}
