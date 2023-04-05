/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This package exports the following C functions:
// - ss_plugin_t* plugin_init(const char* config, int32_t* rc, const ss_plugin_init_input* input)
// - void* plugin_destroy(ss_plugin_t* s)
//
// The exported plugin_init calls the function set with SetOnInit, which
// returns a sdk.PluginState interface. If the return value implements the
// sdk.ExtractRequests interface, the function checks if an instance of
// sdk.ExtractRequestPool has already been set. If not, a default
// one is created on the fly and set with the SetExtractRequests method.
//
// The exported plugin_destroy requires s to be a handle
// of cgo.Handle from this SDK. If the value of the s handle implements
// the sdk.Destroyer interface, the function calls its Destroy method.
// If any of sdk.ExtractRequests, sdk.LastErrorBuffer, sdk.StringerBuffer,
// or sdk.ProgresserBuffer, are implemented, the function calls the Free method
// on the returned sdk.StringBuffer. Finally, the function deletes the
// s cgo.Handle.
//
// This function is part of the plugin_api interface as defined in plugin_api.h.
// In almost all cases, your plugin should import this module, unless your
// plugin exports those symbols by other means.
package initialize

/*
#include <stdint.h>
#include "../../plugin_types.h"
static void log_helper(ss_plugin_log_func f, void* owner, ss_plugin_log_severity sev, const char* msg) { f(owner, sev, msg); }
*/
import "C"
import (
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/cgo"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/internal/hooks"
)

type PluginLogger struct {
	loggingCallBack C.ss_plugin_log_func
	owner           unsafe.Pointer
	enabledSeverity uint32
	buf             ptr.StringBuffer
}

// Not sure if we need to return an error
func (p *PluginLogger) Warn(msg string) error {
	/* We want to remove all useless call */
	if p.enabledSeverity < sdk.SSPluginSevWarning {
		return nil
	}
	p.buf.Write(msg)
	C.log_helper(p.loggingCallBack, p.owner, (C.ss_plugin_log_severity)(sdk.SSPluginSevWarning), (*C.char)(p.buf.CharPtr()))
	return nil
}

func (p *PluginLogger) Info(msg string) error {
	if p.enabledSeverity < sdk.SSPluginSevInfo {
		return nil
	}
	p.buf.Write(msg)
	C.log_helper(p.loggingCallBack, p.owner, (C.ss_plugin_log_severity)(sdk.SSPluginSevInfo), (*C.char)(p.buf.CharPtr()))
	return nil
}

func (p *PluginLogger) SetCallback(cb C.ss_plugin_log_func) {
	p.loggingCallBack = cb
}

func (p *PluginLogger) SetOwner(owner unsafe.Pointer) {
	p.owner = owner
}

func (p *PluginLogger) SetEnabledSev(sev uint32) {
	p.enabledSeverity = sev
}

type baseInit struct {
	lastErr    error
	lastErrBuf ptr.StringBuffer
}

func (b *baseInit) LastError() error {
	return b.lastErr
}

func (b *baseInit) SetLastError(err error) {
	b.lastErr = err
}

func (b *baseInit) LastErrorBuffer() sdk.StringBuffer {
	return &b.lastErrBuf
}

// OnInitFn is a callback used in plugin_init.
type OnInitFn func(config string) (sdk.PluginState, error)

var (
	onInitFn OnInitFn = func(config string) (sdk.PluginState, error) { return &baseInit{}, nil }
)

// SetOnInit sets an initialization callback to be called in plugin_init to
// create the plugin state. If never set, a default one is provided internally.
func SetOnInit(fn OnInitFn) {
	if fn == nil {
		panic("plugin-sdk-go/sdk/symbols/initialize.SetOnInit: fn must not be nil")
	}
	onInitFn = fn
}

//export plugin_init
func plugin_init(config *C.char, rc *int32, init *C.ss_plugin_init_input) C.uintptr_t {
	var state sdk.PluginState
	var err error

	state, err = onInitFn(C.GoString(config))
	if err != nil {
		state = &baseInit{}
		state.(sdk.LastError).SetLastError(err)
		*rc = sdk.SSPluginFailure
	} else {
		// this allows a nil state
		extrReqs, ok := state.(sdk.ExtractRequests)
		if ok && extrReqs.ExtractRequests() == nil {
			extrReqs.SetExtractRequests(sdk.NewExtractRequestPool())
		}

		// If the plugin is a Logger consumer set we set a Logger
		if logCons, ok := state.(sdk.LoggerConsumer); ok {
			logger := &PluginLogger{}
			logger.SetCallback(init.log)
			logger.SetOwner(init.owner)
			logger.SetEnabledSev(uint32(init.min_sev))
			logCons.SetLogger(logger)
		}

		*rc = sdk.SSPluginSuccess
	}

	handle := cgo.NewHandle(state)
	if *rc == sdk.SSPluginSuccess {
		hooks.OnAfterInit()(handle)
	}

	return (C.uintptr_t)(handle)
}

//export plugin_destroy
func plugin_destroy(pState C.uintptr_t) {
	if pState != 0 {
		handle := cgo.Handle(pState)
		hooks.OnBeforeDestroy()(handle)
		if state, ok := handle.Value().(sdk.Destroyer); ok {
			state.Destroy()
		}
		if state, ok := handle.Value().(sdk.ExtractRequests); ok {
			state.ExtractRequests().Free()
			state.SetExtractRequests(nil)
		}
		if state, ok := handle.Value().(sdk.LastErrorBuffer); ok {
			state.LastErrorBuffer().Free()
		}
		if state, ok := handle.Value().(sdk.StringerBuffer); ok {
			state.StringerBuffer().Free()
		}
		if state, ok := handle.Value().(sdk.ProgressBuffer); ok {
			state.ProgressBuffer().Free()
		}
		handle.Delete()
	}
}
