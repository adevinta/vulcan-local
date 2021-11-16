/*
Copyright 2021 Adevinta
*/

package sqsservice

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/p4tin/goaws/app/conf"
	"github.com/p4tin/goaws/app/gosqs"
	"github.com/p4tin/goaws/app/router"
	"github.com/phayes/freeport"
	"github.com/sirupsen/logrus"
)

const goa = `
Local:
  Host: goaws
  Port: ${PORT}
  AccountId: "${ACCOUNTID}"
  QueueAttributeDefaults:
    VisibilityTimeout: 30
    ReceiveMessageWaitTimeSeconds: 0
  Queues:
    - Name: Checks
    - Name: Status
`
const accountId = "01234567901"

type SQSServer struct {
	Endpoint  string
	ArnChecks string
	ArnStatus string
	quit      chan struct{}
}

func Start(l log.Logger) (*SQSServer, error) {
	// This sets the loglevel for gosqs
	logrus.SetLevel(logrus.ErrorLevel)

	port, err := freeport.GetFreePort()
	if err != nil {
		return nil, fmt.Errorf("unable to find a port %+v", err)
	}

	{ // Configure goaaws trough a temp config file.
		goaConfig := strings.ReplaceAll(goa, "${PORT}", strconv.Itoa(port))
		goaConfig = strings.ReplaceAll(goaConfig, "${ACCOUNTID}", accountId)
		tmpFile, err := ioutil.TempFile(os.TempDir(), "")
		if err != nil {
			return nil, fmt.Errorf("unable to create tmpfile %+v", err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.Write([]byte(goaConfig))
		tmpFile.Close()
		ports := conf.LoadYamlConfig(tmpFile.Name(), "")
		if ports == nil {
			return nil, fmt.Errorf("unable to load config %s", goa)
		}
		if ports[0] != strconv.Itoa(port) {
			return nil, fmt.Errorf("port mismatch %v %d", ports, port)
		}
	}

	// The service has to be accesible just by this same go process. No need to expose on all interfaces
	addr := fmt.Sprintf("localhost:%d", port)
	endpoint := fmt.Sprintf("http://%s/", addr)

	l.Debugf("Starting sqs server on %s", endpoint)
	go func() {
		http.ListenAndServe(addr, router.New())
	}()

	quit := make(chan struct{})
	go gosqs.PeriodicTasks(1*time.Second, quit)

	return &SQSServer{
		Endpoint:  endpoint,
		ArnChecks: fmt.Sprintf("arn:aws:sqs::%s:Checks", accountId),
		ArnStatus: fmt.Sprintf("arn:aws:sqs::%s:Status", accountId),
		quit:      quit,
	}, nil
}

func (s *SQSServer) Shutdown() {
	s.quit <- struct{}{}
}
