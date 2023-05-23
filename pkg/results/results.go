/*
Copyright 2021 Adevinta
*/

package results

import (
	"fmt"
	"sync"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	report "github.com/adevinta/vulcan-report"
)

type ResultsServer struct {
	Checks map[string]*report.Report
	log    log.Logger
	mu     sync.Mutex
}

func Start(l log.Logger) (*ResultsServer, error) {
	r := ResultsServer{
		Checks: make(map[string]*report.Report),
		log:    l,
	}
	return &r, nil
}

func (srv *ResultsServer) UploadCheckData(checkID, kind string, startedAt time.Time, content []byte) (string, error) {
	if kind == "reports" {
		report := &report.Report{}
		if err := report.UnmarshalJSONTimeAsString(content); err != nil {
			srv.log.Errorf("Unable to decode %s %v", string(content), err)
			return "", err
		}
		srv.log.Debugf("check-status id=%s status=%s", checkID, report.Status)
		srv.mu.Lock()
		srv.Checks[checkID] = report
		srv.mu.Unlock()
		return "", nil
	}
	if kind == "logs" {
		srv.log.Debugf("check-logs id=%s\n%s\n\n", checkID, string(content))
		return "", nil
	}
	return "", fmt.Errorf("unknown kind %s", kind)
}
