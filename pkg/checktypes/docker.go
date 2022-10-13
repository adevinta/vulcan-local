/*
Copyright 2021 Adevinta
*/

package checktypes

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// buildDockerImage builds and image given a tar, a list of tags and labels.
func buildDockerdImage(tarFile io.Reader, tags []string, labels map[string]string) (response string, err error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	buildOptions := types.ImageBuildOptions{
		Tags:   tags,
		Labels: labels,
		Remove: true,
	}

	re, err := cli.ImageBuild(ctx, tarFile, buildOptions)
	if err != nil {
		return "", err
	}

	lines, err := readDockerOutput(re.Body)
	return strings.Join(lines, "\n"), err
}

func imageInfo(image string) (map[string]string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	filter := filters.KeyValuePair{
		Key:   "reference",
		Value: image,
	}
	options := types.ImageListOptions{
		Filters: filters.NewArgs(filter),
	}
	infos, error := cli.ImageList(ctx, options)
	if error != nil {
		return nil, err
	}
	var labels = make(map[string]string)
	for _, info := range infos {
		for k, v := range info.Labels {
			labels[k] = v
		}
	}
	return labels, nil
}

func readDockerOutput(r io.Reader) (lines []string, err error) {
	reader := bufio.NewReader(r)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Function will return error only if it's not a EOF.
				err = nil
			}
			return lines, err
		}

		lines = append(lines, line)

		msg, err := parseDockerAPIResultLine(line)
		if err != nil {
			return nil, err
		}

		if msg.ErrorDetail != nil {
			err = errors.New(msg.ErrorDetail.Message)
			return nil, err
		}
	}
}

type dockerAPIResp struct {
	Status      string               `json:"status,omitempty"`
	ErrorDetail *types.ErrorResponse `json:"errorDetail,omitempty"`
}

func parseDockerAPIResultLine(line string) (imgResp *dockerAPIResp, err error) {
	imgResp = &dockerAPIResp{}
	err = json.Unmarshal([]byte(line), imgResp)
	return
}
