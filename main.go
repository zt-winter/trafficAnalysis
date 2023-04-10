package main

import (
	"os"
	"runtime/debug"
	"runtime/pprof"
)

func main() {
	cpuf, err := os.OpenFile("cpu.pprof", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}
	defer cpuf.Close()
	pprof.StartCPUProfile(cpuf)
	defer pprof.StopCPUProfile()

	memoryf, err := os.OpenFile("memory.pprof", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}
	defer memoryf.Close()
	pprof.WriteHeapProfile(memoryf)

	config := readConfig()
	//setMemoryLimit中参数单位为字节
	debug.SetMemoryLimit(15 << 30)
	debug.SetGCPercent(-1)
	extractFeature(config)
}
