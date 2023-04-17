package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// 后续补充
type CONFIG struct {
	Method      string `json:"method"`
	Device      string `json:"device"`
	Filter      string `json:"filter"`
	Tuple       string `json:"tuple"`
	PacpFileDir string `json:"pcapFileDir"`
	SaveFileDir string `json:"saveFileDir"`
	SaveMode    string `json:"saveMode"`
	KafkaSource string `json:"kafkaSource"`
	KafkaTopic  string `json:"kafkaTopic"`
}

func readConfig() CONFIG {
	var config CONFIG
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		fmt.Println("decoder error")
		log.Fatal(err)
	}
	return config
}
