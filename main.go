package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
)

func readMemoryAt(address int64, processHandle windows.Handle) uint32 {
	var (
		data   [4]byte
		length uint32
	)

	// BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
	procReadProcessMemory.Call(
		uintptr(processHandle),
		uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&length)),
	)

	bits := binary.LittleEndian.Uint32(data[:])
	// float := math.Float32frombits(bits)
	return bits
}

func getProcessId(name string) (uint32, error) {
	// unsafe.Sizeof(windows.ProcessEntry32{})
	const processEntrySize = 568

	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return 0, e
	}
	p := windows.ProcessEntry32{Size: processEntrySize}
	for {
		e := windows.Process32Next(h, &p)
		if e != nil {
			return 0, e
		}
		if windows.UTF16ToString(p.ExeFile[:]) == name {
			return p.ProcessID, nil
		}
	}
}

func main() {
	processId, e := getProcessId("TestCarai.exe")
	if e != nil {
		panic(e)
	}

	// Open the process with read and write access
	processHandle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, processId)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Read the memory at the specific address ( 4 bytes)
	address := 0x1F2C6C24604
	a := readMemoryAt(int64(address), processHandle)
	fmt.Println(a)
}
