/*
Copyright 2022 Adevinta
*/

package content

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidScheme is returned by the `content` method of the `URI` struct
// when it cannot read the content because its schema is not supported.
var ErrInvalidScheme = errors.New("invalid schema")

// Download downloads the content of an URL, the supported schemas are: http,
// https and file (which is the default if url does not have a schema). For the
// http and https schemas it dowloads the content using a GET request.
func Download(u *url.URL) ([]byte, error) {
	if u == nil {
		return nil, errors.New("url can't be nil")
	}
	if u.String() == "" {
		return nil, errors.New("empty uri")
	}

	if u.Scheme == "http" || u.Scheme == "https" {
		client := http.Client{
			Timeout: time.Second * 10,
		}
		req, err := http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("unable to request uri %s: %w", u, err)
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("unable to get uri %s: %w", u, err)
		}
		if res.Body != nil {
			defer res.Body.Close()
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read uri %s: %w", u, err)
		}
		return body, nil
	}
	if u.Scheme == "file" || u.Scheme == "" {
		// Note that we want an url like: file://dir1/dir2 to be interpreted as
		// having the path dir1/dir2, eventought that's not strictly correct.
		// That's the reason we are trimming directly the url string and not
		// using the path fragment of the parsed URL.
		path := strings.TrimPrefix(u.String(), "file://")
		body, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("unable to read file %s: %w", u, err)
		}
		return body, nil
	}

	return nil, fmt.Errorf("%w in %s", ErrInvalidScheme, u.String())
}
