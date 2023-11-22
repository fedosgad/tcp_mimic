package main

import (
	"github.com/chifflier/nfqueue-go/nfqueue"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	q := new(nfqueue.Queue)

	_ = q.SetCallback(NFQCallback)

	err := q.Init()
	if err != nil {
		log.Fatal(err)
	}

	err = q.Unbind(syscall.AF_INET)
	if err != nil {
		log.Fatal(err)
	}
	_ = q.Bind(syscall.AF_INET)

	err = q.CreateQueue(0)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = q.DestroyQueue()
		q.Close()
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.StopLoop()
		}
	}()

	err = q.Loop()
	if err != nil {
		log.Fatal(err)
	}
}
