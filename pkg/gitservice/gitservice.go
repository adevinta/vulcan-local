/*
Copyright 2021 Adevinta
*/

package gitservice

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/go-git/go-git/v5"
	"github.com/jesusfcr/gittp"
	"github.com/otiai10/copy"
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
	path, err := gs.create_tmp_repository(path)
	if err != nil {
		return 0, err
	}
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

func (gs *gitService) create_tmp_repository(path string) (string, error) {
	tmp_repository_path := filepath.Join(os.TempDir(), "vulcan-local-tmp-repository")
	err := copy.Copy(path, tmp_repository_path)
	os.RemoveAll(filepath.Join(tmp_repository_path, ".git"))
	gs.log.Debugf("Copied %s to %s", path, tmp_repository_path)
	if err != nil {
		gs.log.Errorf("Error coping tmp file: %s", err)
		return "", err
	}
	repository, _ := git.PlainInit(tmp_repository_path, false)
	w, err := repository.Worktree()
	if err != nil {
		gs.log.Errorf("Error opening worktree: %s", err)
		return "", err
	}
	w.AddGlob(".")
	_, err = w.Commit("", &git.CommitOptions{})
	if err != nil {
		gs.log.Errorf("Error committing: %s", err)
		return "", err
	}
	return tmp_repository_path, nil
}
