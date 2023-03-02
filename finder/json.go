package finder

import (
	"github.com/antchfx/jsonquery"
	"os"
)

func GetDocumentFromFile(filename string) *jsonquery.Node {
	// Get JSON file
	f, err := os.Open(filename)
	// Parse JSON file
	input, err := jsonquery.Parse(f)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}
	return input
}

/*
-----------------------------------------
Interesting info extraction section
-----------------------------------------
*/
func GetTitlePagesByQuery(document *jsonquery.Node, query []string) []string {
	return getValuesFromEntriesViaContains(document, "url", "title", query)
}

func GetTechPages(document *jsonquery.Node, queryContains []string) []string {
	return getValuesFromEntriesViaContains(document, "url", "tech", queryContains)
}

func GetPort80Pages(document *jsonquery.Node) []string {
	query := []string{"':80'"}
	return getValuesFromEntriesViaContains(document, "url", "url", query)
}

func GetSelfSignedPages(document *jsonquery.Node) []string {
	return getValuesFromEntriesMatchBoolean(document, "url", "self_signed", true)
}

func GetWebserverTypes(document *jsonquery.Node) []string {
	return GetValuesFromEntriesAll(document, "webserver")
}

func GetUrls(document *jsonquery.Node) []string {
	return GetValuesFromEntriesAll(document, "url")
}

/*
 HELPER FUNCTIONS
*/

func getValuesFromEntriesViaContains(document *jsonquery.Node, key string, queryKey string, queryContains []string) []string {
	var result []string

	for _, query := range queryContains {
		entries, error := jsonquery.QueryAll(document, "//*/"+queryKey+"[contains(.,"+query+")]")

		if error != nil {
			log.Errorf("Querying JSON error   #%v ", error)
		}

		for _, entry := range entries {

			if entryValues, ok := entry.Parent.Value().(map[string]interface{}); ok {
				values, exists := entryValues[key]
				if exists {
					if value, ok := values.(string); ok {
						if key == "url" {
							result = AppendIfMissing(result, GetHost(value))
						} else {
							result = AppendIfMissing(result, value)
						}
					}
				}
			}
		}
	}

	return result
}

func getValuesFromEntriesMatchBoolean(document *jsonquery.Node, key string, queryKey string, matchCondition bool) []string {
	var result []string
	var query string

	if matchCondition {
		query = "//*[" + queryKey + "='true']"
	} else {
		query = "//*[" + queryKey + "='false']"
	}
	entries, error := jsonquery.QueryAll(document, query)
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	for _, entry := range entries {

		if entryValues, ok := entry.Parent.Value().(map[string]interface{}); ok {
			values, exists := entryValues[key]
			if exists {
				if value, ok := values.(string); ok {
					if key == "url" {
						result = AppendIfMissing(result, GetHost(value))
					} else {
						result = AppendIfMissing(result, value)
					}
				}
			}
		}
	}
	return result
}

func getAllNodesByContains(document *jsonquery.Node, key string, queryKey string, queryContains []string) []*jsonquery.Node {

	var results []*jsonquery.Node

	for _, query := range queryContains {
		entries, error := jsonquery.QueryAll(document, "//*/"+queryKey+"[contains(.,"+query+")]")

		if error != nil {
			log.Errorf("Querying JSON error   #%v ", error)
		}

		for _, entry := range entries {
			results = append(results, entry)
		}
	}

	return results
}

func GetAllNodesByKey(document *jsonquery.Node, key string) []*jsonquery.Node {
	entries, error := jsonquery.QueryAll(document, "//"+key)

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	return entries
}

func GetSingleValueFromEntriesAll(document *jsonquery.Node, key string) string {

	entries, error := jsonquery.QueryAll(document, "//"+key)
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	if len(entries) == 1 {
		if entryValues, ok := entries[0].Parent.Value().(map[string]interface{}); ok {
			values, exists := entryValues[key]
			if exists {
				if value, ok := values.(string); ok {
					return value
				}

			}
		}
	}
	return ""
}

func GetValuesFromEntriesAll(document *jsonquery.Node, key string) []string {
	var result []string
	entries, error := jsonquery.QueryAll(document, "//"+key)
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	for _, entry := range entries {

		if entryValues, ok := entry.Parent.Value().(map[string]interface{}); ok {
			values, exists := entryValues[key]
			if exists {
				if value, ok := values.(string); ok {
					if key == "url" {
						result = AppendIfMissing(result, GetHost(value))
					} else {
						if url, ok := entryValues["url"].(string); ok {
							completeValue := value + " (" + url + ")"
							result = AppendIfMissing(result, completeValue)
						}

					}
				} else if value, ok := values.([]interface{}); ok {
					if key == "subject_an" {
						for _, val := range value {
							if entry, ok := val.(string); ok {
								result = AppendIfMissing(result, entry)
							}
						}
					}
				}
			}
		}
	}
	return result
}
