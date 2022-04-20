package config

import (
	"encoding/json"
	"os"
	"log"
)

//后续补充
type CONFIG struct {
	Method string `json:"method"`
	Device string `json:"device"`
	Filter string `json:"filter"`
	PacpFile string `json:"pcap_file"`
	FeatureFile string `json:"feature_file"`
}

func ReadConfig() CONFIG {
	var config CONFIG
	file, err := os.Open("./config.json")
	if err != nil {
		log.Fatal(err)
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatal(err)
	}
	return config
}
