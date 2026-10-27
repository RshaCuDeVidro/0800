// Command lab starts deliberately vulnerable services on localhost so the
// scanner can be exercised without touching anything real.
//
//	go run ./tools/lab
//	go run . -t 127.0.0.1 --plain
//
// Every service binds 127.0.0.1 only.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/RshaCuDeVidro/0800/internal/lab"
)

func main() {
	var (
		smbPort   = flag.Int("smb", 1445, "SMB port (445 needs root)")
		mysqlPort = flag.Int("mysql", 3306, "MySQL port")
		pgPort    = flag.Int("postgres", 5432, "PostgreSQL port")
		redisPort = flag.Int("redis", 6379, "Redis port")
		nfsPort   = flag.Int("nfs", 2049, "NFS port")
		mountPort = flag.Int("mountd", 20048, "MOUNT port")
	)
	flag.Parse()

	l := &lab.Lab{}
	defer l.Close()

	fail := func(name string, err error) {
		fmt.Fprintf(os.Stderr, "  %-10s failed: %v\n", name, err)
	}

	if svc, err := lab.NewSMB(lab.SMBConfig{SMB1: true, Signing: "disabled", NullOK: true}).Start(*smbPort); err != nil {
		fail("smb", err)
	} else {
		l.Add(svc.Name, svc.Listener)
	}
	if svc, err := lab.StartMySQL(*mysqlPort); err != nil {
		fail("mysql", err)
	} else {
		l.Add(svc.Name, svc.Listener)
	}
	if svc, err := lab.StartPostgres(*pgPort); err != nil {
		fail("postgres", err)
	} else {
		l.Add(svc.Name, svc.Listener)
	}
	if svc, err := lab.StartRedis(*redisPort); err != nil {
		fail("redis", err)
	} else {
		l.Add(svc.Name, svc.Listener)
	}
	if svcs, err := lab.StartNFS(*nfsPort, *mountPort); err != nil {
		fail("nfs", err)
	} else {
		for _, svc := range svcs {
			l.Add(svc.Name, svc.Listener)
		}
	}

	fmt.Println()
	fmt.Println("  0800 lab — deliberately vulnerable, localhost only")
	fmt.Println()
	fmt.Print(l.String())
	fmt.Println()
	fmt.Println("  scan it with:  go run . -t 127.0.0.1 -p 3306,5432,6379,2049 --remap smb=1445 --plain")
	fmt.Println("  press ctrl+c to stop")
	fmt.Println()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
