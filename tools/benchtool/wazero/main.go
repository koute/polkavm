package main

import "C"
import (
	"context"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"log"
	"sync"
	"unsafe"
)

type refMap[T any] struct {
	lock sync.RWMutex
	m    map[uint64]*T
	last uint64
}

func ref_map_new[T any]() refMap[T] {
	return refMap[T]{m: make(map[uint64]*T)}
}

func (rm *refMap[T]) add(value *T) uint64 {
	rm.lock.Lock()
	id := rm.last
	rm.last += 1
	rm.m[id] = value
	rm.lock.Unlock()
	return id
}

func (rm *refMap[T]) get(id uint64) *T {
	rm.lock.RLock()
	val := rm.m[id]
	rm.lock.RUnlock()
	return val
}

func (rm *refMap[T]) remove(id uint64) {
	rm.lock.Lock()
	delete(rm.m, id)
	rm.lock.Unlock()
}

var engines refMap[tyEngine] = ref_map_new[tyEngine]()
var modules refMap[tyModule] = ref_map_new[tyModule]()
var instances refMap[tyInstance] = ref_map_new[tyInstance]()

type tyEngine struct {
	ctx context.Context
	r   wazero.Runtime
}

type tyModule struct {
	mod wazero.CompiledModule
}

type tyInstance struct {
	ctx        context.Context
	instance   api.Module
	initialize api.Function
	run        api.Function
}

func create() *tyEngine {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	return &tyEngine{r: r, ctx: ctx}
}

func compile(engine *tyEngine, blob []byte) *tyModule {
	mod, err := engine.r.CompileModule(engine.ctx, blob)
	if err != nil {
		log.Panicf("failed to compile module: %v", err)
	}

	return &tyModule{mod}
}

func instantiate(engine *tyEngine, module *tyModule) *tyInstance {
	config := wazero.NewModuleConfig()
	instance, err := engine.r.InstantiateModule(engine.ctx, module.mod, config)
	if err != nil {
		log.Panicf("failed to instantiate module: %v", err)
	}

	initialize := instance.ExportedFunction("initialize")
	run := instance.ExportedFunction("run")
	ctx := engine.ctx
	return &tyInstance{ctx, instance, initialize, run}
}

func initialize(instance *tyInstance) {
	_, err := instance.initialize.Call(instance.ctx)
	if err != nil {
		log.Panicf("failed to call initialize: %v", err)
	}
}

func run(instance *tyInstance) {
	_, err := instance.run.Call(instance.ctx)
	if err != nil {
		log.Panicf("failed to call run: %v", err)
	}
}

//export Engine_new
func Engine_new() uint64 {
	return engines.add(create())
}

//export Engine_drop
func Engine_drop(handle uint64) {
	engine := engines.get(handle)
	engines.remove(handle)
	engine.r.Close(engine.ctx)
}

//export Module_new
func Module_new(engine_h uint64, blob_ptr unsafe.Pointer, blob_len C.int) uint64 {
	engine := engines.get(engine_h)
	blob := C.GoBytes(blob_ptr, blob_len)
	module := compile(engine, blob)
	return modules.add(module)
}

//export Module_drop
func Module_drop(module_h uint64) {
	modules.remove(module_h)
}

//export Instance_new
func Instance_new(engine_h uint64, module_h uint64) uint64 {
	engine := engines.get(engine_h)
	module := modules.get(module_h)
	instance := instantiate(engine, module)
	return instances.add(instance)
}

//export Instance_initialize
func Instance_initialize(instance_h uint64) {
	initialize(instances.get(instance_h))
}

//export Instance_run
func Instance_run(instance_h uint64) {
	run(instances.get(instance_h))
}

//export Instance_drop
func Instance_drop(instance_h uint64) {
	instances.remove(instance_h)
}

func main() {}
