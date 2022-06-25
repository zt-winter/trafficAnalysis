package main

import (
	"os"
	"fmt"
)

func main() {
	/*
	pprof.StartCPUProfile(os.Stdout)
	defer pprof.StopCPUProfile()
	*/
	arg := os.Args
	if len(arg) < 2 {
		fmt.Println("no give pcapfile")
	}
	config := readConfig()
	for i := 1; i < len(arg); i++ {
		extractFeature(config, arg[i])
	}
}
