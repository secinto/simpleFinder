package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/secinto/simpleFinder/finder"
)

func main() {
	// Parse the command line flags and read config files
	options := finder.ParseOptions()

	newFinder, err := finder.NewFinder(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create pusher: %s\n", err)
	}

	err = newFinder.Find()
	if err != nil {
		gologger.Fatal().Msgf("Could not push: %s\n", err)
	}
}
