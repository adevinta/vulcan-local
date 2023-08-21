// Package dockerutil provides Docker utility functions.
package dockerutil

import (
	"context"
	"fmt"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// GetGateways returns the gateways of the specified Docker network.
func GetGateways(ctx context.Context, cli *client.Client, network string) ([]net.IP, error) {
	resp, err := cli.NetworkInspect(ctx, network, types.NetworkInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("network inspect: %w", err)
	}

	var gws []net.IP
	for _, cfg := range resp.IPAM.Config {
		gw := net.ParseIP(cfg.Gateway)
		if gw == nil {
			return nil, fmt.Errorf("invalid IP %q", cfg.Gateway)
		}
		gws = append(gws, gw)
	}

	return gws, nil
}
