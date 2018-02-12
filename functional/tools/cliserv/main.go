package main

import (
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"strconv"
	//	"github.com/stackimpact/stackimpact-go"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type mode string

const (
	client mode = "client"
	server      = "server"
)

var usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of cliserv:\n")
	fmt.Fprintln(os.Stderr, "\tcliserv -port XXXX [OPTIONS]")
	fmt.Fprintln(os.Stderr, "\n\tWhere XXXX is a valid port number.")
	fmt.Fprintln(os.Stderr, "\nOPTIONS:")
	flag.PrintDefaults()
}

func main() {
	/*
		agent := stackimpact.Start(stackimpact.Options{
			AgentKey: "42798fcb61b19b5f0d43d23ee7ac1353fdf64092",
			AppName:  "MyGoApp",
			Debug:    true,
		})
	*/
	//println(agent.DashboardAddress)

	port := flag.Int("port", -1, "Port used to listen for incoming requests. Mandatory.")
	remoteHost := flag.String("remoteHost", "", "Remote host name or IP used to send requests. You must specify remotePort to use this option.")
	remotePort := flag.Int("remotePort", -1, "Port used to send requests to remote host.")
	p := flag.Int("period", 2000, "Milliseconds the client should wait between requests to remote host. By default 2000 ms. Used only when remoteHost is specified.")

	flag.Parse()

	if *port == -1 || *remoteHost != "" && *remotePort == -1 {
		usage()
		return
	}

	period := time.Duration(*p)

	logfile := "cliserv_" + strconv.Itoa(*port) + ".log"
	f, err := os.OpenFile(logfile, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer f.Close()

	log := logrus.New()
	log.Out = f

	// Create channel for interrupt signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	if *remotePort != -1 {
		client := newClient(log, *remoteHost, *remotePort, period)
		client.Run()
	}
	server := newServer(log, *port)
	server.Run()

	<-interrupt
	log.Info("interrupted! will exit")
}
