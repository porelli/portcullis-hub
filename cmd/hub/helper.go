package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/hub/internal/volcopy"
)

// Helper subcommands (contract §6 "On Kubernetes", §3.4, §13.7), run in
// helper pods and init containers from the Hub's own image; dispatched
// before any environment is read, like `hub folderfix`:
//
//	hub helper idle                 sleep until SIGTERM (the helper pod's main process)
//	hub helper listen <addr>        accept TCP connections, answer "ok" (netpol probe)
//	hub helper dial <ip:port>       connect within 3 s; exit 0 = reached
//	hub volcopy out <dir>           <dir> as a tar on stdout ("data/…" entries)
//	hub volcopy in <dir>            extract a tar from stdin into <dir>
//	hub seed <src> <dst>            copy src/. into dst when dst is empty (K4)
//	hub rev <dir>                   print <dir>/.rev (exit 1 when missing)
func helperMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: hub helper|volcopy|seed|rev …")
		return 2
	}
	var err error
	switch {
	case args[0] == "helper" && len(args) == 2 && args[1] == "idle":
		err = idle()
	case args[0] == "helper" && len(args) == 3 && args[1] == "listen":
		err = listen(args[2])
	case args[0] == "helper" && len(args) == 3 && args[1] == "dial":
		err = dial(args[2])
	case args[0] == "volcopy" && len(args) == 3 && args[1] == "out":
		err = volcopy.Out(args[2], stdout)
	case args[0] == "volcopy" && len(args) == 3 && args[1] == "in":
		err = volcopy.In(args[2], stdin)
	case args[0] == "seed" && len(args) == 3:
		err = volcopy.Seed(args[1], args[2])
	case args[0] == "rev" && len(args) == 2:
		var rev string
		if rev, err = volcopy.Rev(args[1]); err == nil {
			fmt.Fprintln(stdout, rev)
		}
	default:
		fmt.Fprintf(stderr, "hub %s: bad arguments\n", strings.Join(args, " "))
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "hub %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// isHelperCommand: args[1] names a helper subcommand.
func isHelperCommand(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[1] {
	case "helper", "volcopy", "seed", "rev":
		return true
	}
	return false
}

func idle() error {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c
	return nil
}

func listen(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(c, "ok\n")
		c.Close()
	}
}

func dial(addr string) error {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return err
	}
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 3)
	_, err = io.ReadFull(c, b)
	c.Close()
	if err != nil || string(b) != "ok\n" {
		return fmt.Errorf("no answer from %s", addr)
	}
	return nil
}
