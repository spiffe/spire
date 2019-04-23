package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

var (
	addrFlag = flag.String("addr", ":8081", "address to bind the echo server to")
	logFlag  = flag.String("log", "", "path to log to (empty=stderr)")
)

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL)
	responseBytes, err := json.Marshal(r.Header)
	if err != nil {
		http.Error(w, "unable to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.Write(responseBytes)
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) (err error) {
	flag.Parse()
	log.SetPrefix("echo> ")
	log.SetFlags(log.Ltime)
	if *logFlag != "" {
		logFile, err := os.OpenFile(*logFlag, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("unable to open log file: %v", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	} else {
		log.SetOutput(os.Stdout)
	}
	log.Printf("starting echo server...")

	ln, err := net.Listen("tcp", *addrFlag)
	if err != nil {
		return fmt.Errorf("unable to listen: %v", err)
	}
	defer ln.Close()

	log.Printf("listening on %s...", ln.Addr())
	server := &http.Server{
		Handler: http.HandlerFunc(handler),
	}
	return server.Serve(ln)
}
