<h1 align="center">simpleFinder</h1>
<h4 align="center">Tool for obtaining pentest findings from JSON files and HTTP request/responses</h4>
<p align="center">
  
  <img src="https://img.shields.io/github/watchers/secinto/simpleFinder?label=Watchers&style=for-the-badge" alt="GitHub Watchers">
  <img src="https://img.shields.io/github/stars/secinto/simpleFinder?style=for-the-badge" alt="GitHub Stars">
  <img src="https://img.shields.io/github/license/secinto/simpleFinder?style=for-the-badge" alt="GitHub License">
</p>

Developed by Stefan Kraxberger (https://twitter.com/skraxberger/)  

Released as open source by secinto GmbH - https://secinto.com/  
Released under Apache License version 2.0 see LICENSE for more information

Description
----
simpleFinder is a GO tool which tries to identify possible interesting URLs and hosts from different sources. 
Input files are mostly JSON output from projectdiscovery tools such as httpx, subfinder, dnsx as well as JSON 
files created from Nmap port scans and webanalyze technology enumeration and others.   
Also, the stored responses, as obtained from httpx are used. In addition, output from feroxBuster and 
ffuf can also be included.

# Installation Instructions

`simpleFinder` requires **go1.20** to install successfully. Run the following command to get the repo:

```sh
git clone https://github.com/secinto/simpleFinder.git
cd simpleFinder
go build
go install
```

or the following to directly install it from the command line:

```sh
go install -v github.com/secinto/simpleFinder/cmd/simpleFinder@latest
```

# Usage

```sh
simpleFinder -help
```

This will display help for the tool. Here are all the switches it supports.


```console
Usage:
  simpleFinder [flags]

Flags:
INPUT:
   -p, -project string  project name for metadata addition
   -email               identify Email security (MX, TXT, ...) for the specified project
   -dns                 identify DNS resolutions for the specified project
   -ports               identify open ports for the specified project
   -all                 perform all checks

CONFIG:
   -config string  settings (Yaml) file location (default "/home/samareina/.config/simpleFinder/settings.yaml")

DEBUG:
   -silent         show only results in output
   -version        show version of the project
   -v              show verbose output
   -nc, -no-color  disable colors in output
