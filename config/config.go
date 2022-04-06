package config

import (
	"encoding/json"
	"fmt"
	"os"
	"log"
)

//后续补充
type CONFIG struct {
	PacpFile string `json:"pcap_file"`
	Filter string `json:"filter"`
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
		fmt.Println("error")
		log.Fatal(err)
	}
	fmt.Println(config)
	return config
}
