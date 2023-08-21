// Package dockerutil provides Docker utility functions.
package dockerutil

import (
	"context"
	"fmt"
	"net"
	"runtime"

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

// GetBridgeHost returns a host that corresponds to the Docker host
// that is reachable from the containers running in the default bridge
// network.
func GetBridgeHost(cli *client.Client) (string, error) {
	if runtime.GOOS != "linux" {
		return "127.0.0.1", nil
	}

	gws, err := GetGateways(context.Background(), cli, "bridge")
	if err != nil {
		return "", fmt.Errorf("could not get Docker network gateway: %w", err)
	}
	if len(gws) != 1 {
		return "", fmt.Errorf("unexpected number of gateways: %v", len(gws))
	}

	return gws[0].String(), nil
}
