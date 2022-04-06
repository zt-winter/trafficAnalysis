package main

import(
	"trafficAnalysis/extract"
	"trafficAnalysis/config"
)


func main() {
	config := config.ReadConfig()
	extract.ExtractFeature(config.PacpFile, config.Filter, config.FeatureFile)
}


