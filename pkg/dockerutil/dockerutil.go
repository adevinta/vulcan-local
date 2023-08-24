// Package dockerutil provides Docker utility functions.
package dockerutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/flags"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/tlsconfig"
)

// NewAPIClient returns a new Docker API client. This client behaves
// as close as possible to the Docker CLI. It gets its configuration
// from the Docker config file and honors the [Docker CLI environment
// variables]. It also sets up TLS authentication if TLS is enabled.
//
// [Docker CLI environment variables]: https://docs.docker.com/engine/reference/commandline/cli/#environment-variables
func NewAPIClient() (client.APIClient, error) {
	tlsVerify := os.Getenv(client.EnvTLSVerify) != ""

	var tlsopts *tlsconfig.Options
	if tlsVerify {
		certPath := os.Getenv(client.EnvOverrideCertPath)
		if certPath == "" {
			certPath = config.Dir()
		}
		tlsopts = &tlsconfig.Options{
			CAFile:   filepath.Join(certPath, flags.DefaultCaFile),
			CertFile: filepath.Join(certPath, flags.DefaultCertFile),
			KeyFile:  filepath.Join(certPath, flags.DefaultKeyFile),
		}
	}

	opts := &flags.ClientOptions{
		TLS:        tlsVerify,
		TLSVerify:  tlsVerify,
		TLSOptions: tlsopts,
	}

	return command.NewAPIClientFromFlags(opts, config.LoadDefaultConfigFile(io.Discard))
}

// Gateways returns the gateways of the specified Docker network.
func Gateways(ctx context.Context, cli client.APIClient, network string) ([]*net.IPNet, error) {
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
func BridgeGateway(cli client.APIClient) (*net.IPNet, error) {
	gws, err := Gateways(context.Background(), cli, "bridge")
	if err != nil {
		return nil, fmt.Errorf("could not get Docker network gateway: %w", err)
	}
	if len(gws) != 1 {
		return nil, fmt.Errorf("unexpected number of gateways: %v", len(gws))
	}
	return gws[0], nil
}

// BridgeHost returns a host that points to the Docker host and is
// reachable from the containers running in the default bridge.
func BridgeHost(cli client.APIClient) (string, error) {
	isDesktop, err := isDockerDesktop(cli)
	if err != nil {
		return "", fmt.Errorf("detect Docker Desktop: %w", err)
	}

	if isDesktop {
		return "127.0.0.1", nil
	}

	gw, err := BridgeGateway(cli)
	if err != nil {
		return "", fmt.Errorf("get bridge gateway: %w", err)
	}
	return gw.IP.String(), nil
}

// isDockerDesktop returns true if the Docker daemon is part of Docker
// Desktop. That means that there is a network interface with the same
// IP of the gateway of the default Docker bridge network.
func isDockerDesktop(cli client.APIClient) (bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("interface addrs: %w", err)
	}

	gw, err := BridgeGateway(cli)
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
