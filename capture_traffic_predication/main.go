package main

import (
	"log"
	"realtime-network-instruction-detection/pkg/capture"
)

func main() {
	interfaceName := `\Device\NPF_Loopback`
	log.Println("Starting capture on loopback interface for web server traffic on port 8000")
	capture.CaptureWebServerTraffic(interfaceName)
}
