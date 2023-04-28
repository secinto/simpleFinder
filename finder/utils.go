package finder

import (
	"bufio"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

var (
	client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func CreateDirectoryIfNotExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0o770)
		if err != nil {
			return err
		}
	}
	return nil
}

func CreateOutputFromInput(input string) string {

	output := strings.ReplaceAll(input, ".json", ".struct.json")
	return output
}

func WriteToTextFileInProject(filename string, data string) {
	writeFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	dataWriter := bufio.NewWriter(writeFile)

	if err != nil {
		log.Error(err)
	}
	dataWriter.WriteString(data)
	dataWriter.Flush()
	writeFile.Close()
}

func ConvertStringArrayToString(stringArray []string, separator string) string {
	sort.Strings(stringArray)
	justString := strings.Join(stringArray, separator)
	return justString
}

func CheckIfArrayContainsString(stringArray []string, stringToCheck string) bool {
	for _, element := range stringArray {
		if strings.Contains(element, stringToCheck) {
			return true
		}
	}
	return false
}

func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func AppendIfMissing(slice []string, key string) []string {
	for _, element := range slice {
		if element == key {
			return slice
		}
	}
	return append(slice, key)
}

func ExistsInArray(slice []string, key string) bool {
	for _, element := range slice {
		if element == key {
			return true
		}
	}
	return false
}

func GetHost(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		return str
	}
	return u.Scheme + "://" + u.Host
}

func ConvertJSONLtoJSON(input string) string {

	var data []byte
	data = append(data, '[')

	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")

	isFirst := true
	for _, line := range lines {
		if !isFirst && strings.TrimSpace(line) != "" {
			data = append(data, ',')
			data = append(data, '\n')
		}
		if strings.TrimSpace(line) != "" {
			data = append(data, line...)
		}
		isFirst = false
	}
	data = append(data, ']')
	return string(data)
}

func CheckIfFileExists(path string, stopRunning bool) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		if stopRunning == true {
			log.Fatal("File " + path + " does not exist!")
			return false
		} else {
			log.Info("File " + path + " does not exist!")
			return false
		}
	}
	if err != nil {
		log.Fatal("Error checking file:", err)
		return false
	}

	return true
}

func getDomainFromString(str string) string {
	var domain string

	parts := strings.Split(str, ".")

	if len(parts) < 2 {
		log.Error("Invalid domain " + str)
	} else {
		domain = parts[0]
	}
	log.Info(domain)
	return domain
}
