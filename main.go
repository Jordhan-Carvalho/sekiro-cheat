package main

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/0xrawsec/golang-win32/win32"
	kernel32 "github.com/0xrawsec/golang-win32/win32/kernel32"
	windows "golang.org/x/sys/windows"
)

var (
	handle                 windows.Handle
	procReadProcessMemory  *windows.Proc
	procWriteProcessMemory *windows.Proc
	baseAddress            int64
	gamePointerOffset      = 0x03AFB218
)

func memoryReadInit(processId uint32) (int64, bool) {
	// handle, _ = windows.OpenProcess(0x0010 | windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION, false, pid)
	handle, _ = windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, processId)

	procReadProcessMemory = windows.MustLoadDLL("kernel32.dll").MustFindProc("ReadProcessMemory")
	procWriteProcessMemory = windows.MustLoadDLL("kernel32.dll").MustFindProc("WriteProcessMemory")

	win32handle, _ := kernel32.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, win32.BOOL(0), win32.DWORD(processId))
	moduleHandles, _ := kernel32.EnumProcessModules(win32handle)
	for _, moduleHandle := range moduleHandles {
		s, _ := kernel32.GetModuleFilenameExW(win32handle, moduleHandle)
		targetModuleFilename := "sekiro.exe"
		if filepath.Base(s) == targetModuleFilename {
			info, _ := kernel32.GetModuleInformation(win32handle, moduleHandle)
			baseAddress = int64(info.LpBaseOfDll)
			return baseAddress, true
		}
	}
	return 0, false
}

func readMemoryAt(address int64) uint32 {
	var (
		data   [4]byte
		length uint32
	)

	// BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
	procReadProcessMemory.Call(
		uintptr(handle),
		uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&length)),
	)

	fmt.Println(data)
	bits := binary.LittleEndian.Uint32(data[:])
	// float := math.Float32frombits(bits)
	return bits
}
func readMemoryAtByte8(address int64) uint64 {
	var (
		data   [8]byte
		length uint32
	)

	procReadProcessMemory.Call(
		uintptr(handle),
		uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&length)),
	)

	byte8 := binary.LittleEndian.Uint64(data[:])
	return byte8
}

func getHealthAddress(baseAdress int64) (int64, int64) {
	// it will game the first pointer values with hard coded offset
	var gamePointerAddress = baseAddress + int64(gamePointerOffset)
	fmt.Println("First pointer value is :", gamePointerAddress)
	pointer2 := readMemoryAtByte8(gamePointerAddress)
	fmt.Println("pointer2 result", pointer2)

	secondOffset := 0x28
	pointer3 := readMemoryAtByte8(int64(pointer2 + uint64(secondOffset)))
	fmt.Println("pointer3 result", pointer3)

	thirdOffset := 0xA40
	pointer4 := readMemoryAtByte8(int64(pointer3) + int64(thirdOffset))
	fmt.Println("pointer4 result", pointer4)

	fourthOffset := 0x6D0
	pointer5 := readMemoryAtByte8(int64(pointer4) + int64(fourthOffset))
	fmt.Println("5 pointer result", pointer5)

	fifthOffset := 0x8
	pointer6 := readMemoryAtByte8(int64(pointer5) + int64(fifthOffset))
	fmt.Println("6 pointer result", pointer6)

	// this time we will read the 4 byte values of the last addres (health data type)
	sixthOffset := 0xFC0
	healthMemoryAddress := pointer6 + uint64(sixthOffset)
	healthValue := readMemoryAt(int64(pointer6) + int64(sixthOffset))
	fmt.Println("health value", healthValue)
	fmt.Println("health address", healthMemoryAddress)

	return int64(healthValue), int64(healthMemoryAddress)
}

func getProcessId(name string) (uint32, error) {
	// unsafe.Sizeof(windows.ProcessEntry32{})
	const processEntrySize = 568

	// create a snapshot of process windows.handle
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return 0, e
	}

	// create a object to hold the process
	/* type ProcessEntry32 struct {
	    Size            uint32
	    Usage           uint32
	    ProcessID       uint32
	    DefaultHeapID   uintptr
	    ModuleID        uint32
	    Threads         uint32
	    ParentProcessID uint32
	    PriClassBase    int32
	    Flags           uint32
	    ExeFile         [MAX_PATH]uint16
	} */
	p := windows.ProcessEntry32{Size: processEntrySize}
	// will loop thru the process snapshot populating the Process object and then it will compare the exe name
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
	processId, e := getProcessId("sekiro.exe")
	if e != nil {
		panic(e)
	}

	// Open the process and populate the global variables and return the base address
	baseAddress, _ := memoryReadInit(processId)
	fmt.Println("Base address is", baseAddress)

  currentHealth, healthAddress := getHealthAddress(baseAddress)
  fmt.Println("currentHealth", currentHealth)

	// Read the memory at the specific address ( 4 bytes)
	a := readMemoryAt(healthAddress)
	fmt.Println(a)

	// write a value at the memory point
	var n uint32 = 300
	var length uint32
	newHealthBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(newHealthBuffer, n)

	procWriteProcessMemory.Call(uintptr(handle), uintptr(healthAddress), uintptr(unsafe.Pointer(&newHealthBuffer[0])), uintptr(len(newHealthBuffer)), uintptr(unsafe.Pointer(&length)))

	// Read again just to check
	b := readMemoryAt(healthAddress)
	fmt.Println(b)
}
