package finder

import (
	"github.com/antchfx/xmlquery"
	"os"
	"strings"
)

func GetXMLDocumentFromFile(filename string) *xmlquery.Node {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}
	xmlReader := strings.NewReader(string(data))
	input, err := xmlquery.Parse(xmlReader)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}

	return input
}
