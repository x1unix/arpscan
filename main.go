package main

import (
	"context"
	"log"
	"sync"
)

func main() {
	ctx := GetApplicationContext()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	ifaces, err := getInterfaces()
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	for _, iface := range ifaces {
		wg.Add(1)
		go scanIface(ctx, wg, iface)
	}

	wg.Wait()
	return nil
}
