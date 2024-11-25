package main

import (
	boladetector "f5/bola/bola_detector"
	"f5/bola/logreader"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Excpecting filename argument")
		os.Exit(1)
	}
	filename := os.Args[1]
	lines, err := logreader.ParseLogFile(filename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	potentialBola := boladetector.DetectBolaAttack(lines)
	if len(potentialBola) > 0 {
		for endpoint, attackLine := range potentialBola {
			fmt.Printf("Potential BOLA attack on Endpoint: %s. attack request in line: %d", endpoint, attackLine)
		}
	} else {
		fmt.Printf("didnt find any potential BOLA")
	}
}
