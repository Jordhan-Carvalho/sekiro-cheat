package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jordhan-carvalho/sekiro-cheat/system"
)


var (
	gamePointerOffset      = 0x03AFB218
)

func getHealthAddress(baseAdress int64) (int64, int64) {
	// it will game the first pointer values with hard coded offset
	var gamePointerAddress = baseAdress + int64(gamePointerOffset);
	pointer2 := system.ReadMemoryAtByte8(gamePointerAddress)
	// fmt.Println("pointer2 result", pointer2)

	secondOffset := 0x28
	pointer3 := system.ReadMemoryAtByte8(int64(pointer2 + uint64(secondOffset)))
	// fmt.Println("pointer3 result", pointer3)

	thirdOffset := 0xA40
	pointer4 := system.ReadMemoryAtByte8(int64(pointer3) + int64(thirdOffset))
	// fmt.Println("pointer4 result", pointer4)

	fourthOffset := 0x6D0
	pointer5 := system.ReadMemoryAtByte8(int64(pointer4) + int64(fourthOffset))
	// fmt.Println("5 pointer result", pointer5)

	fifthOffset := 0x8
	pointer6 := system.ReadMemoryAtByte8(int64(pointer5) + int64(fifthOffset))
	// fmt.Println("6 pointer result", pointer6)

	// this time we will read the 4 byte values of the last addres (health data type)
	sixthOffset := 0xFC0
	healthMemoryAddress := pointer6 + uint64(sixthOffset)
	healthValue := system.ReadMemoryAt(int64(pointer6) + int64(sixthOffset))
	// fmt.Println("health value", healthValue)
	// fmt.Println("health address", healthMemoryAddress)

	return int64(healthValue), int64(healthMemoryAddress)
}



func periodicallySetHealth(newHealth uint32, healthMemoryAdress int64, period time.Duration) {
	t := time.NewTicker(period * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C: // Activate periodically
      system.WriteAtMemory4Bytes(newHealth, healthMemoryAdress)
		}
	}
}

func main() {
	processId, e := system.GetProcessId("sekiro.exe")
	if e != nil {
		panic(e)
	}

	// Open the process and populate the global variables and return the base address
	baseAddress, _ := system.MemoryReadInit(processId)

	currentHealth, healthAddress := getHealthAddress(baseAddress)
	fmt.Println("currentHealth", currentHealth)

  // Run a function periodically
	var newHealth uint32 = 320
  go periodicallySetHealth(newHealth, healthAddress, 1)

	// Wait here until CTRL-C or other term signal is received.
	log.Println("Health cheat is now running. Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	// If anything needs to gracefully shutdown... put it here
  // like the go routine running periodicaclly
}
