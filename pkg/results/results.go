/*
Copyright 2021 Adevinta
*/

package results

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"

	"github.com/adevinta/vulcan-agent/log"
	report "github.com/adevinta/vulcan-report"
	"github.com/julienschmidt/httprouter"
)

type ReportPayload struct {
	CheckId   string `json:"check_id,omitempty"`
	ReportRaw string `json:"report,omitempty"`
}

type LogsPayload struct {
	CheckId string `json:"check_id,omitempty"`
	B64Logs string `json:"raw,omitempty"`
}

type ResultsServer struct {
	Endpoint string
	Checks   map[string]*report.Report
	done     chan error
	server   *http.Server
	log      log.Logger
	mu       sync.Mutex
}

func Start(l log.Logger) (*ResultsServer, error) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// The service has to be accesible just by this same go process. No need to expose on all interfaces
	addr := fmt.Sprintf("localhost:%d", port)
	endpoint := fmt.Sprintf("http://%s/", addr)

	r := ResultsServer{
		Endpoint: endpoint,
		Checks:   make(map[string]*report.Report),
		done:     make(chan error),
		log:      l,
	}

	router := httprouter.New()
	router.POST("/report", r.handleReport)
	router.POST("/raw", r.handleLogs)

	r.server = &http.Server{Addr: addr, Handler: router}
	l.Debugf("Starting results server on %s", endpoint)
	go func() {
		err := r.server.Serve(listener)
		r.done <- err
		close(r.done)
	}()

	return &r, nil
}

func (srv *ResultsServer) Shutdown() {
	srv.server.Shutdown(context.Background())
	err := <-srv.done
	if err != http.ErrServerClosed {
		srv.log.Errorf("Error stoping http server: %+v", err)
	}
}

func (srv *ResultsServer) handleReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(err.Error()))
		return
	}

	if string(payload) == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte("body can not be empty"))
		return
	}

	pl := &ReportPayload{}
	err = json.Unmarshal(payload, pl)
	if err != nil {
		srv.log.Errorf("Unable to decode %s %v", string(payload), err)
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(err.Error()))
		return
	}

	report := &report.Report{}
	err = json.Unmarshal([]byte(pl.ReportRaw), report)
	if err != nil {
		srv.log.Errorf("Unable to decode %s %v", string(pl.ReportRaw), err)
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(err.Error()))
		return
	}

	srv.log.Debugf("check-status id=%s status=%s", pl.CheckId, report.Status)
	srv.mu.Lock()
	srv.Checks[pl.CheckId] = report
	srv.mu.Unlock()

	w.Header().Add("location", "http://dummy/report/"+pl.CheckId)
	w.WriteHeader(http.StatusCreated)
}

func (srv *ResultsServer) handleLogs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(err.Error()))
		return
	}

	if string(payload) == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte("body can not be empty"))
		return
	}

	pl := &LogsPayload{}
	err = json.Unmarshal(payload, pl)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(err.Error()))
		return
	}

	sDec, _ := base64.StdEncoding.DecodeString(pl.B64Logs)

	srv.log.Debugf("check-logs id=%s\n%s\n\n", pl.CheckId, string(sDec))

	w.Header().Add("location", "http://dummy/raw/"+pl.CheckId)
	w.WriteHeader(http.StatusCreated)
}
