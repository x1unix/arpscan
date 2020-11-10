package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var once = &sync.Once{}

var (
	ctx        context.Context
	cancelFunc context.CancelFunc
)

// GetApplicationContext returns application context for graceful shutdown
func GetApplicationContext() context.Context {
	once.Do(func() {
		ctx, cancelFunc = context.WithCancel(context.Background())

		go func() {
			signals := []os.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT}
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, signals...)
			defer signal.Reset(signals...)
			<-sigChan
			cancelFunc()
		}()
	})

	return ctx
}

