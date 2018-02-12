package main

import (
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

type RemoteWL struct {
	host string
	port int
}

type ClientWL struct {
	log        *logrus.Logger
	server     *RemoteWL
	period     time.Duration
	statusPort string
}

func newClient(log *logrus.Logger, serverHost string, serverPort int, period time.Duration) *ClientWL {
	return &ClientWL{
		log:    log,
		server: &RemoteWL{host: serverHost, port: serverPort},
		period: period,
	}
}

func (c *ClientWL) Run() {
	go func() {
		c.log.Info("client started!")

		serverURL := "http://" + c.server.host + ":" + strconv.Itoa(c.server.port) + "/"

		// Main loop
		for {
			url := serverURL + "ping"
			c.log.Infof("GET %v", url)
			resp, err := http.Get(url)
			if err != nil {
				c.log.Infof("error executing GET %v: %v", url, err)
			} else {
				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					c.log.Infof("error reading body from GET %v: %v", url, err)
				} else {
					c.log.Infof("response received: %v - %s", resp.StatusCode, body)
				}
			}
			time.Sleep(c.period * time.Millisecond)
		}
	}()
}
