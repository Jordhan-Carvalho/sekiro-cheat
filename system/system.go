package system

import (
	"encoding/binary"
	"log"
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
)

func MemoryReadInit(processId uint32) (int64, bool) {
	// handle, _ = windows.OpenProcess(0x0010 | windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION, false, pid)
  var e error
	handle, e = windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, processId)
  if e != nil {
    log.Println("YOU MUST RUN AS ADMIN", e)
  }

	procReadProcessMemory = windows.MustLoadDLL("kernel32.dll").MustFindProc("ReadProcessMemory")
	procWriteProcessMemory = windows.MustLoadDLL("kernel32.dll").MustFindProc("WriteProcessMemory")

	win32handle, _ := kernel32.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, win32.BOOL(0), win32.DWORD(processId))
	moduleHandles, _ := kernel32.EnumProcessModules(win32handle)
	for _, moduleHandle := range moduleHandles {
		s, _ := kernel32.GetModuleFilenameExW(win32handle, moduleHandle)
		targetModuleFilename := "sekiro.exe"
		if filepath.Base(s) == targetModuleFilename {
			info, _ := kernel32.GetModuleInformation(win32handle, moduleHandle)
			baseAddress := int64(info.LpBaseOfDll)
			return baseAddress, true
		}
	}
	return 0, false
}

func ReadMemoryAt(address int64) uint32 {
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

	bits := binary.LittleEndian.Uint32(data[:])
	// float := math.Float32frombits(bits)
	return bits
}

func ReadMemoryAtByte8(address int64) uint64 {
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

func WriteAtMemory4Bytes(data uint32, memoryAdress int64) {
	// write a value at the memory point
	var length uint32
	dataBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(dataBuffer, data)

	procWriteProcessMemory.Call(uintptr(handle), uintptr(memoryAdress), uintptr(unsafe.Pointer(&dataBuffer[0])), uintptr(len(dataBuffer)), uintptr(unsafe.Pointer(&length)))
}

func GetProcessId(name string) (uint32, error) {
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
