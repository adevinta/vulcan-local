/*
Copyright 2021 Adevinta
*/

package gitservice

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/jesusfcr/gittp"
	"github.com/phayes/freeport"
)

type GitService interface {
	AddGit(path string) (int, error)
	Shutdown()
}

type gitMapping struct {
	port   int
	server *http.Server
}

type gitService struct {
	log      log.Logger
	mappings map[string]*gitMapping
	wg       sync.WaitGroup
}

func New(l log.Logger) GitService {
	return &gitService{
		mappings: make(map[string]*gitMapping),
		log:      l,
	}
}

func (gs *gitService) AddGit(path string) (int, error) {
	if mapping, ok := gs.mappings[path]; ok {
		return mapping.port, nil
	}
	config := gittp.ServerConfig{
		Path:       path,
		Debug:      false,
		PreCreate:  gittp.UseGithubRepoNames,
		PreReceive: gittp.MasterOnly,
	}
	handle, err := gittp.NewGitServer(config)
	if err != nil {
		return 0, err
	}
	port, err := freeport.GetFreePort()
	if err != nil {
		return 0, err
	}

	r := gitMapping{
		port:   port,
		server: &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", port), Handler: handle},
	}
	gs.mappings[path] = &r
	gs.wg.Add(1)
	gs.log.Debugf("Starting git server path=%s port=%d", path, port)
	go func() {
		r.server.ListenAndServe()
		defer gs.wg.Done()
	}()
	return port, nil
}

func (gs *gitService) Shutdown() {
	for _, m := range gs.mappings {
		m.server.Shutdown(context.Background())
	}
	gs.wg.Wait()
}
