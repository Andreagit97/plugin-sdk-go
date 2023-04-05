// package logging

// // typedef void (*log_cb)(int, const char*);
// // static void log_helper(log_cb f, int v, const char* msg) { f(v, msg); }
// import "C"
// import (
// 	"log"

// 	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
// )

// type Severity int

// const (
// 	FATAL Severity = iota + 1
// 	CRITICAL
// 	ERROR
// 	WARNING
// 	NOTICE
// 	INFO
// 	DEBUG
// 	TRACE
// )

// var (
// 	loggingCallBack C.log_cb = nil
// 	buf             ptr.StringBuffer
// )

// func Log(sev Severity, msg string) {
// 	if loggingCallBack != nil {
// 		log.Println("Logging enabled go-side")
// 		buf.Write(msg)
// 		C.log_helper(loggingCallBack, (C.int)(sev), (*C.char)(buf.CharPtr()))
// 		return
// 	}
// 	// something else...
// 	log.Println("Logging not enabled go-side")
// }

// //export plugin_register_logging_callback
// func plugin_register_logging_callback(cb C.log_cb) {
// 	loggingCallBack = cb
// }
