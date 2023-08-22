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
func GetGateways(ctx context.Context, cli *client.Client, network string) ([]*net.IPNet, error) {
	resp, err := cli.NetworkInspect(ctx, network, types.NetworkInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("network inspect: %w", err)
	}

	var gws []*net.IPNet
	for _, cfg := range resp.IPAM.Config {
		_, subnet, err := net.ParseCIDR(cfg.Subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet: %v", cfg.Subnet)
		}

		ip := net.ParseIP(cfg.Gateway)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %v", cfg.Gateway)
		}

		subnet.IP = ip
		gws = append(gws, subnet)
	}
	return gws, nil
}

// GetBridgeHost returns the gateway of the default Docker bridge
// network.
func GetBridgeGateway(cli *client.Client) (*net.IPNet, error) {
	gws, err := GetGateways(context.Background(), cli, "bridge")
	if err != nil {
		return nil, fmt.Errorf("could not get Docker network gateway: %w", err)
	}
	if len(gws) != 1 {
		return nil, fmt.Errorf("unexpected number of gateways: %v", len(gws))
	}
	return gws[0], nil
}

// GetBridgeHost returns a host that points to the Docker host and is
// reachable from the containers running in the default bridge.
func GetBridgeHost(cli *client.Client) (string, error) {
	isDesktop, err := isDockerDesktop(cli)
	if err != nil {
		return "", fmt.Errorf("detect Docker Desktop: %w", err)
	}

	if isDesktop {
		return "127.0.0.1", nil
	}

	gw, err := GetBridgeGateway(cli)
	if err != nil {
		return "", fmt.Errorf("get bridge gateway: %w", err)
	}
	return gw.IP.String(), nil
}

// isDockerDesktop returns true if the Docker daemon is part of Docker
// Desktop. That means that there is a network interface with the same
// IP of the gateway of the default Docker bridge network.
func isDockerDesktop(cli *client.Client) (bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("interface addrs: %w", err)
	}

	gw, err := GetBridgeGateway(cli)
	if err != nil {
		return false, fmt.Errorf("get bridge gateway: %w", err)
	}

	for _, addr := range addrs {
		if gw.String() == addr.String() {
			return false, nil
		}
	}
	return true, nil

}
