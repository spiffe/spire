package main

import (
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strconv"
)

type ServerWL struct {
	log  *logrus.Logger
	port int
}

func newServer(log *logrus.Logger, port int) *ServerWL {
	return &ServerWL{log: log, port: port}
}

func (s *ServerWL) status(w http.ResponseWriter, req *http.Request) {
	s.log.Infof("%v - %v %v", req.RemoteAddr, req.Method, req.URL)
	io.WriteString(w, "I'm up and running!")
}

func (s *ServerWL) ping(w http.ResponseWriter, req *http.Request) {
	s.log.Infof("%v - %v %v", req.RemoteAddr, req.Method, req.URL)
	io.WriteString(w, "pong")
}

func (s *ServerWL) Run() {
	go func() {
		s.log.Infof("started listening on port %v!", s.port)
		http.HandleFunc("/status", s.status)
		http.HandleFunc("/ping", s.ping)
		s.log.Fatal(http.ListenAndServe(":"+strconv.Itoa(s.port), nil))
	}()
}
