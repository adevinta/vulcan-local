/*
Copyright 2021 Adevinta
*/

package checktypes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/adevinta/vulcan-agent/log"

	"github.com/adevinta/vulcan-local/pkg/content"
)

// ChecktypeRef represents a checktype with an optional prefix denoting the
// repository (i.e. default/vulcan-zap vulcan-zap ).
type ChecktypeRef string

// Checktype defines the data about a concrete checktype.
type Checktype struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Timeout      int                    `json:"timeout,omitempty"`
	Image        string                 `json:"image"`
	Options      map[string]interface{} `json:"options,omitempty"`
	RequiredVars []string               `json:"required_vars"`
	QueueName    string                 `json:"queue_name,omitempty"`
	Assets       []string               `json:"assets"`
}

// Checktypes contains a collection of checktypes indexed by checktype name.
type Checktypes map[ChecktypeRef]Checktype

// Checktype returns a pointer to the a Checktype given is reference if it
// exists, otherwise it returns an error.
func (c Checktypes) Checktype(ref ChecktypeRef) (*Checktype, error) {
	if ct, ok := c[ref]; ok {
		return &ct, nil
	}
	return nil, fmt.Errorf("unable to find checktype ref %s", ref)
}

// JSONChecktypes defines the shape of a file containing the definition of a
// set of checkstypes.
type JSONChecktypes struct {
	Checktypes []Checktype `json:"checktypes"`
}

// Import loads the information of the checktypes defined in the specified repos
// url's.
func Import(repos []string, l log.Logger) (map[ChecktypeRef]Checktype, error) {
	var checktypes = make(map[ChecktypeRef]Checktype)
	for _, repo := range repos {
		l.Debugf("Importing checktype from: %s", repo)
		repoURL, err := neturl.Parse(repo)
		if err != nil {
			return nil, err
		}
		rchecktypes, err := checktypesFrom(repoURL, l)
		if err != nil {
			return nil, fmt.Errorf("unable to load repository %s: %w", repo, err)
		}
		for _, checktype := range rchecktypes {
			ref := ChecktypeRef(checktype.Name)
			checktypes[ref] = checktype
		}
	}
	return checktypes, nil
}

func checktypesFrom(u *neturl.URL, l log.Logger) ([]Checktype, error) {
	if u.Scheme == "code" {
		return checktypesFromCode(u, l)
	}
	return checktypesFromJSON(u, l)
}

func checktypesFromJSON(u *neturl.URL, l log.Logger) ([]Checktype, error) {
	content, err := content.Download(u)
	if err != nil {
		return nil, err
	}
	jchecktypes := struct {
		Checktypes []Checktype `json:"checktypes"`
	}{}
	err = json.Unmarshal(content, &jchecktypes)
	if err != nil {
		return nil, err
	}
	var checktypes = make([]Checktype, len(jchecktypes.Checktypes))
	for _, c := range jchecktypes.Checktypes {
		checktypes = append(checktypes, c)
	}
	l.Debugf("Loaded checktypes info from url=%s, number of checktypes loaded=%d", u.String(), len(jchecktypes.Checktypes))
	return checktypes, nil
}

func checktypesFromCode(u *neturl.URL, l log.Logger) ([]Checktype, error) {
	path := strings.TrimPrefix(u.String(), "code://")
	l.Debugf("Loading checktypes from code in: %s", path)
	dirInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !dirInfo.IsDir() {
		return nil, fmt.Errorf("a code repository must point to a dir: %s", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("error reading code checktypes repository %s: %v", path, err)
	}
	var checktypes []Checktype
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dirpath := filepath.Join(path, e.Name())
		l.Debugf("examing if directory %s contains the code of a check", dirpath)
		manifestPath := filepath.Join(dirpath, "manifest.toml")
		l.Debugf("trying to read manifest from %s", manifestPath)
		m, err := ReadManifest(manifestPath)
		// We consider a directory to be contain the code of a check if it has
		// a manifest.
		if errors.Is(err, fs.ErrNotExist) {
			l.Debugf("The directory %s doesn't contains the code of a check", dirpath)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error reading manifest file %s, %v", manifestPath, err)
		}
		options, err := m.UnmarshalOptions()
		if err != nil {
			return nil, fmt.Errorf("invalid options in manifest %s: %w", manifestPath, err)
		}
		assets, err := m.AssetTypes.Strings()
		if err != nil {
			return nil, fmt.Errorf("invalid asset types in manifest %s: %w", manifestPath, err)
		}

		ct := Checktype{
			Name:         e.Name(),
			Description:  m.Description,
			Timeout:      m.Timeout,
			Image:        fmt.Sprintf("code://%s", dirpath),
			Options:      options,
			RequiredVars: m.RequiredVars,
			Assets:       assets,
		}
		checktypes = append(checktypes, ct)
	}
	return checktypes, nil

}
