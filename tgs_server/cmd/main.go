package main

import (
	"flag"
	"log"

	"security-project/tgs_server/service"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config json")
	flag.Parse()
	svc := service.NewService(*configPath)
	if err := svc.Run(); err != nil {
		log.Fatal(err)
	}
}
