# vulcan-local

vulcan-local allows to execute security checks locally.

- Is part of **Vulcan vulnerability scanning** ecosystem. See <https://adevinta.github.io/vulcan-docs/>
- Leverages [vulcan-checks](https://github.com/adevinta/vulcan-checks) catalog.
- The checks are executed in your local machine or in a CI/CD pipeline.
- Only `docker` and `git` are required.
- The checks can access local assets.
  - Local directories.
  - Local docker images.
  - Local http applications.

For those reasons this tool can be a good fit to move left security.

## Requirements

- Docker has to be running on the local machine.
- Git.
- Go (for development)

## Installing

From source code

```sh
# Last release version
go install github.com/adevinta/vulcan-local@latest
```

Install binary releases

```sh
# Install last release
curl -sfL https://raw.githubusercontent.com/adevinta/vulcan-local/master/script/get | sh

# Install specific version
curl -sfL https://raw.githubusercontent.com/adevinta/vulcan-local/master/script/get | sh -s -- --version v0.0.1

# Show available options
curl -sfL https://raw.githubusercontent.com/adevinta/vulcan-local/master/script/get | sh -s -- --help
Accepted cli arguments are:
  [--help|-h ] ->> prints this help
  [--version|-v <desired_version>] . When not defined it fetches the latest release from GitHub
  [--no-sudo]  ->> install without sudo
  [--run|--] ... ->> Skip install and run the downloaded vulcan-local temp binary with the extra params

# Executing without installing
curl -sfL https://raw.githubusercontent.com/adevinta/vulcan-local/master/script/get | sh -s -- \
  --run -t .
```

## Executing

See some examples

```sh
# Show available options
vulcan-local -h

# Scan current directory as a git repo with the default checktypes.
vulcan-local -t .

# Scan a remote public docker image
vulcan-local -t alpine:latest -a DockerImage

# Build and scan a local image
echo "FROM alpine" | docker build -t myimg -
vulcan-local -t myimg -a DockerImage

# Scan the local http endpoint with the custom checktypes.
docker run -d -p 1234:80 --name myapp nginx
vulcan-local -t http://localhost:1234 -i exposed

# Execute all checks on WebAddress that doesn't matches 'zap' regex.
vulcan-local -t http://localhost:1234 -e zap

# Execute all checks on WebAddress with the indicated option.
vulcan-local -t http://localhost:1234 -o '{"depth": 1}'

# Execute all checks . inferring the asset type.
vulcan-local -t .

# See the report in json
vulcan-local -t . -r - -l ERROR | jq .

# Pass variables trough command line (those examples are equivalent)
vulcan-local -t https://wordpress.org -i wpscan -v WPVULNDB_API_TOKEN
vulcan-local -t https://wordpress.org -i wpscan -v WPVULNDB_API_TOKEN=$WPVULNDB_API_TOKEN
```

Also the tool can be used to scan remote resources.

```sh
# Scan a list of assets for CRITICAL vulns with trivy exporting the results in json.
cat myimages.txt | awk '{print "-t " $0 " -a DockerImage"}' \
  | xargs -p vulcan-local -i trivy -s CRITICAL -r report.json

# Scan all the AWS internet-facing LoadBalancers in one account with all checks available.
aws elbv2 describe-load-balancers \
  | jq -r '.LoadBalancers[] | select( .Scheme == "internet-facing") | .DNSName' \
  | awk '{print "-t " $0}' \
  | xargs -p vulcan-local -s HIGH -r report.json
```

## Exit codes

`vulcan-local` generates meaningful exit codes.

Exit codes:

- 0: No vulnerability found over the severity threshold (see -s flag)
- 1: An error happened
- 101: Max severity found was LOW
- 102: Max severity found was MEDIUM
- 103: Max severity found was HIGH
- 104: Max severity found was CRITICAL

Those exit codes can be used in automated systems like CI/CD to control
execution of the pipelines. See example below.

```sh
#!/bin/bash

# Exit the script in case of error
set -e

docker build . -t example.com/org/myimg:latest

# Exit script in case of CRITICAL/HIGH vulnerabilities
vulcan-local -t . -t example.com/org/myimg:latest -s HIGH

docker push example.com/org/myimg:latest
```

## vulcan.yaml config file

This tool accepts a configuration file that wraps all the parameters.

An example file is provided in [vulcan.yaml](./vulcan.yaml).

The main sections are:

- conf/vars: Some config vars sent to the checks, i.e. to allow access to private resources.
- conf/repositories: http or file uris pointing to checktype definitions.
- targets: Contains the list of targets to scan. The tool will generate all the possible checks from the checktypes available.
- checks: The list of additional specific checks to run.
- reporting: Configuration about how to show the results, exclusions, ...

This is a very simple config file with two checks:

```yaml
conf:
  repositories:
    - ./resources/checktypes.json

# List of targets to scan generating checks from all available checktypes
targets:
  - target: .
  - target: http://localhost:1234/

# List of specific additional checks to run
checks:
  # Check current path
  - type: vulcan-gitleaks
    target: .

reporting:
```

### Exclusions

In case the tool reports a finding that should be excluded from the next scans, it is possible to apply some filtering.

When specified, it applies a `contains` evaluation over the following fields:

- summary
- affectedResource: Applies either to `affectedResource` and `affectedResourceString`
- target
- fingerprint
- description: A brief explanation as to why the finding should be excluded from the report.

```yaml
reporting:
  exclusions:
    - summary: Leaked
    - affectedResource: libgcrypt
      target: .
      description: "libgcrypt has a known and accepted vulnerability."
    - affectedResource: busybox
      target: .
      description: "busybox is not relevant"
    - affectedResource: ncurses
      target: latest
    - fingerprint: 7820aa24a96f0fcd4717933772a8bc89552a0c1509f3d90b14d885d25e60595f
```

### Policies

Policies in vulcan-local are intended to abstract the overhead selecting checks and options to scan a given target. By default, policies are loaded from the [internal-policies.yaml](https://raw.githubusercontent.com/adevinta/vulcan-local/master/resources/internal-policies.yaml) file.

Use `-p` to set a policy for the scan. Existing default policies are:
|Policy|Checks included|Target Asset Type|
|--|--|--|
|`internal-static`|[vulcan-semgrep](https://github.com/adevinta/vulcan-checks/tree/master/cmd/vulcan-semgrep)<br> [vulcan-gitleaks](https://github.com/adevinta/vulcan-checks/tree/master/cmd/vulcan-gitleaks)<br>[vulcan-trivy](https://github.com/adevinta/vulcan-checks/tree/master/cmd/vulcan-trivy)| Git repository <br>Directory|
|`internal-web`|[vulcan-retirejs](https://github.com/adevinta/vulcan-checks/tree/master/cmd/vulcan-retirejs)<br>[vulcan-zap](https://github.com/adevinta/vulcan-checks/tree/master/cmd/vulcan-zap)<br>[vulcan-exposed-http](https://github.com/adevinta/vulcan-checks/tree/master/cmd/vulcan-exposed-http)| URL<br>Hostname |

Example:
```sh
vulcan-local -p internal-static -t .
```

Custom policies can be also loaded from a configuration file (local or remote) using `-c` , and then the policy to apply can be set using the parameter `-p`, for example:

```sh
# Configuration file set through an env variable
export VULCAN_CONFIG=https://example.com/custom-policies.yaml
# Run vulcan-local with 'my-policy'
vulcan-local -p my-policy -t .

# or just
vulcan-local -c ./custom-policies.yaml -p my-policy -t .
```

## Running custom checks

Every check is a docker image that needs to be pulled from a registry.

We provide public images for the [vulcan-checks](https://github.com/vulcan-checks).

### Running checks from private registries

This application does not handle authentication in private registries
instead it assumes the current docker client is already authenticated in the required registries.
If the check images are from private registries first login into the registry.

```sh
cat ~/my_password.txt | docker login --username foo --password-stdin private.registry.com
```

### Running checks from source code

`vulcan-local` can run checks which code is stored locally, to do so point the
checktypes param to a directory containing the code of the checktypes to run.
For instance, the following command runs the `vulcan-nuclei` check, by building
and running the code and the docker image in the directory
`vulcan-checks/cmd/vulcan-nuclei` against the hostname: `example.com`

```bash
git clone https://github.com/adevinta/vulcan-checks/

## Make some changes in vulcan-checks/cmd i.e. in vulcan-nuclei.

vulcan-local -checktypes "./vulcan-checks/cmd" -t example.com -a Hostname -l debug -i vulcan-nuclei
```

At this moment, all the available checks are implemented in [Go](https://go.dev).
For that reason it's required to have `go` installed in the system.

## Docker usage

Using the existing docker image:

```sh
docker pull adevinta/vulcan-local:latest
```

Building your local docker image:

```sh
docker build . -t vulcan-local
```

In the following examples the local image reference `vulcan-local` will e used.

Start the target application

```sh
docker run -p 1234:8000 --restart unless-stopped -d appsecco/dsvw
```

Start scan using a local config file

```sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $PWD:/target \
    -e TRAVIS_BUILD_DIR=/target -e REGISTRY_SERVER -e REGISTRY_USERNAME -e REGISTRY_PASSWORD \
    vulcan-local -c /target/vulcan.yaml
```

Start scanning a local http server

```sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    vulcan-local -t http://localhost:1234
```

Start scanning a local directory

```sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD:/src \
  vulcan-local -t /src
```
