package main

import (
	"runtime/pprof"
	"os"
	"trafficAnalysis/config"
	"trafficAnalysis/extract"
)


func main() {
	pprof.StartCPUProfile(os.Stdout)
	defer pprof.StopCPUProfile()
	config := config.ReadConfig()
	extract.ExtractFeature(config)
}
