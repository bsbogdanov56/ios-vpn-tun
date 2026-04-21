package main

// #include <stdlib.h>
import "C"

import (
	"encoding/json"
	"math"
	"sync"
	"unsafe"
)

var (
	proxyHandlesMu sync.Mutex
	proxyHandles   = make(map[int32]*proxyInstance)
)

//export VKTurnStartProxy
func VKTurnStartProxy(configJSON *C.char) int32 {
	if configJSON == nil {
		return -1
	}
	var cfg proxyConfig
	if err := json.Unmarshal([]byte(C.GoString(configJSON)), &cfg); err != nil {
		return -1
	}
	instance, err := newProxyInstance(cfg)
	if err != nil {
		return -1
	}
	proxyHandlesMu.Lock()
	defer proxyHandlesMu.Unlock()
	for i := int32(0); i < math.MaxInt32; i++ {
		if _, ok := proxyHandles[i]; ok {
			continue
		}
		instance.handle = i
		proxyHandles[i] = instance
		instance.start()
		return i
	}
	return -1
}

//export VKTurnStopProxy
func VKTurnStopProxy(handle int32) {
	proxyHandlesMu.Lock()
	instance, ok := proxyHandles[handle]
	if ok {
		delete(proxyHandles, handle)
	}
	proxyHandlesMu.Unlock()
	if ok {
		instance.stop()
	}
}

//export VKTurnGetStatus
func VKTurnGetStatus(handle int32) *C.char {
	proxyHandlesMu.Lock()
	instance, ok := proxyHandles[handle]
	proxyHandlesMu.Unlock()
	if !ok {
		return C.CString(`{"state":"not_found","error":"handle not found"}`)
	}
	return C.CString(instance.statusJSON())
}

// VKTurnSubmitCaptcha delivers user-entered captcha text to the proxy instance.
// Returns 0 on success, -1 otherwise.
//
//export VKTurnSubmitCaptcha
func VKTurnSubmitCaptcha(handle int32, answer *C.char) int32 {
	if answer == nil {
		return -1
	}
	ans := C.GoString(answer)
	proxyHandlesMu.Lock()
	instance, ok := proxyHandles[handle]
	proxyHandlesMu.Unlock()
	if !ok {
		return -1
	}
	if instance.submitCaptcha(ans) {
		return 0
	}
	return -1
}

//export VKTurnFreeString
func VKTurnFreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func main() {}
