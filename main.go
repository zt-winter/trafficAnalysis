package main

import (
	/*
		"runtime/pprof"
		"os"
	*/
)


func main() {
	/*
	pprof.StartCPUProfile(os.Stdout)
	defer pprof.StopCPUProfile()
	*/
	config := ReadConfig()
	extractFeature(config)
}
