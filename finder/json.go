package finder

import (
	"github.com/antchfx/jsonquery"
	"os"
	"strings"
)

func GetJSONDocumentFromFile(filename string) *jsonquery.Node {
	// Get JSON file
	//f, err := os.Open(filename)
	// Parse JSON file
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}
	jsonlString := ConvertJSONLtoJSON(string(data))
	jsonReader := strings.NewReader(jsonlString)
	input, err := jsonquery.Parse(jsonReader)
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

func GetValueForQueryKey(document *jsonquery.Node, requestedField string, queryKey string, query []string) []string {
	return getValuesFromEntriesViaContains(document, requestedField, queryKey, query)
}

func GetValueForQueryBoolean(document *jsonquery.Node, requestedField string, queryKey string, matchCondition bool) []string {
	return getValuesFromEntriesMatchBoolean(document, requestedField, queryKey, matchCondition)
}

func GetAllValuesForKey(document *jsonquery.Node, key string) []string {
	return getValuesFromAllEntries(document, key)
}

func GetAllRecordsForKey(document *jsonquery.Node, key string) []*jsonquery.Node {
	return getAllNodesForKey(document, key)
}

/*
 HELPER FUNCTIONS
*/

// query = test
// {"test1":"..", "test2":..,"asdfasdftest":..,*}
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

// {"queryKey":"query" => "key":...}
func getNodesFromSpecificQueryViaEquals(document *jsonquery.Node, queryKey string, query string) []*jsonquery.Node {
	//var result []string

	entries, error := jsonquery.QueryAll(document, "*["+queryKey+"='"+query+"']")

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}
	return entries
}

// *[isbn='0-553-21311-3']
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

func getAllNodesByContains(document *jsonquery.Node, queryKey string, queryContains []string) []*jsonquery.Node {

	var results []*jsonquery.Node

	for _, query := range queryContains {
		entries, error := jsonquery.QueryAll(document, "//*/"+queryKey+"[contains(.,'"+query+"')]")

		if error != nil {
			log.Errorf("Querying JSON error   #%v ", error)
		}

		for _, entry := range entries {
			results = append(results, entry)
		}
	}

	return results
}

func getValuesForKey(document *jsonquery.Node, key string) []string {
	var result []string

	entries, error := jsonquery.QueryAll(document, "//*")

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	for _, entry := range entries {

		if entryValues, ok := entry.Value().(map[string]interface{}); ok {
			values, exists := entryValues[key]
			if exists {
				if entries, ok := values.([]interface{}); ok {
					for _, subValues := range entries {
						if subValue, ok := subValues.(string); ok {
							result = AppendIfMissing(result, subValue)
						}
					}
				} else {
					if value, ok := values.(string); ok {
						result = AppendIfMissing(result, value)
					}
				}
			}
		}
	}

	return result

}

func getAllNodesForKey(document *jsonquery.Node, key string) []*jsonquery.Node {
	entries, error := jsonquery.QueryAll(document, "//*["+key+"]")

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	return entries
}

func getValuesFromAllEntries(document *jsonquery.Node, key string) []string {
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
func getValuesFromAllNodes(nodes []*jsonquery.Node, key string) []string {
	var result []string
	for _, recordEntry := range nodes {

		if entryValues, ok := recordEntry.Value().(map[string]interface{}); ok {
			values, exists := entryValues[key]
			if exists {
				if entries, ok := values.([]interface{}); ok {
					for _, subValues := range entries {
						if subValue, ok := subValues.(string); ok {
							result = AppendIfMissing(result, subValue)
						}
					}
				} else {
					if entry, ok := values.(string); ok {
						result = AppendIfMissing(result, entry)
					}
				}
			}
		}
	}
	return result
}

func getValuesFromNode(node *jsonquery.Node, key string) []string {
	var result []string

	if entryValues, ok := node.Value().(map[string]interface{}); ok {
		values, exists := entryValues[key]
		if exists {
			if entries, ok := values.([]interface{}); ok {
				for _, subValues := range entries {
					if subValue, ok := subValues.(string); ok {
						result = AppendIfMissing(result, subValue)
					}
				}
			} else {
				if entry, ok := values.(string); ok {
					result = AppendIfMissing(result, entry)
				}
			}
		}
	}
	return result
}
