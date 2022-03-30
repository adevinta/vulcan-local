# vulcan-local

## ⚠️ Alpha status

This tool is under active development and for sure will break compatibility until it gets a stable release.

## Installing

From source code

```sh
# Last release version
go install github.com/adevinta/vulcan-local@latest

# The master version
go install github.com/adevinta/vulcan-local@master
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

## vulcan.yaml config file

This tool accepts a configuration file.

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
    - file://./script/checktypes-stable.json

# List of targets to scan generating checks from all available checktypes
targets:
  - target: .
  - target: http://localhost:1234/

# List of specific checks to run
checks:
  # Check current path
  - type: vulcan-seekret
    target: .

  # Check with default options
  - type: vulcan-zap
    target: http://localhost:1234

reporting:

```

## Executing

Requirements:

- Docker has to be running on the local machine.
- Git

Usage:

```sh
Usage of vulcan-local:
  -a value
    	asset type of the last target (-t)
  -c value
    	config file (i.e. -c vulcan.yaml). Can be used multiple times. (Also env VULCAN_LOCAL_CONFIG)
  -concurrency int
    	max number of checks/containers to run concurrently (default 3)
  -docker string
    	docker binary (default "docker")
  -e string
    	exclude checktype regex
  -git string
    	git binary (default "git")
  -h	print usage
  -i string
    	include checktype regex
  -ifname string
    	network interface where agent will be available for the checks (default "docker0")
  -l value
    	log level [panic fatal error warning info debug trace] (default info)
  -o value
    	options related to the last target (-t) used in all the their checks (i.e. '{"depth":"1", "max_scan_duration": 1}')
  -p string
      policy to be applied to configure the checks and options to be run
  -pullpolicy value
    	when to pull for check images [Always IfNotPresent Never]
  -r string
    	results file (i.e. -r results.json)
  -s value
    	filter by severity [CRITICAL HIGH MEDIUM LOW INFO] (default HIGH)
  -t value
    	target to scan. Can be used multiple times.
  -u value
    	checktype uris. Can be used multiple times. (Also env VULCAN_CHECKTYPES_URI)
  -version
    	print version
```

Exit codes:

- 0: No vulnerability found over the severity threshold (see -s flag)
- 1: An error happened
- 101: Max severity found was LOW
- 102: Max severity found was MEDIUM
- 103: Max severity found was HIGH
- 104: Max severity found was CRITICAL

Scanning the checks defined in vulcan.yaml

```sh
vulcan-local -c vulcan.yaml
```

NOTE: This application does not handle authentication in private registries
instead it assumes the current docker client is already authenticated in the required registries.
If the check images are from private registries first login into the registry.

```sh
cat ~/my_password.txt | docker login --username foo --password-stdin private.registry.com
```

Scan a single asset with all the checkTypes that apply

```sh
vulcan-local -t http://localhost:1234 -i exposed -u file://./script/checktypes-stable.json

# Set VULCAN_CHECKTYPES_URI as the default checktypes uri (-u flag)
export VULCAN_CHECKTYPES_URI=file://./script/checktypes-stable.json

# Execute all checks on WebAddress that matches 'exposed' regex
vulcan-local -t http://localhost:1234 -i exposed

# Execute all checks on WebAddress that doesn't matches 'zap' regex
vulcan-local -t http://localhost:1234 -e zap

# Execute all checks on WebAddress with the indicated option.
vulcan-local -t http://localhost:1234 -o '{"depth": 1}'

# Execute all checks for GitRepository targets (. has to be the root of a git repo)
vulcan-local -t . -a GitRepository

# Execute all checks . inferring the asset type
vulcan-local -t .

```

### Policies

Policies for vulcan-local are intended to abstract the overhead selecting the checks and options to scan any valid target.

A local or remote file can be configured to load policies, and then the policy to apply can be set using the parameter `-p`, for example:

```sh
# Configuration file set through an env variable
export VULCAN_LOCAL_CONFIG=https://raw.githubusercontent.com/adevinta/vulcan-local/master/script/vulcan-policies.yaml

# Run vulcan-local with the lightweight policy
vulcan-local -c vulcan.yaml -p lightweight
```

_This feature is under development, and existing policies were created just for testing purposes._

### Exclusions

In case the tool reports a finding that should be excluded from the next scans, it is possible to apply some filtering.

When specified, it applies a `contains` evaluation over the following fields:

- summary
- affectedResource: Applies either to `affectedResource` and `affectedResourceString`
- target
- fingerprint

```yaml
reporting:
  exclusions:
    - summary: Leaked
    - affectedResource: libgcrypt
      target: .
    - affectedResource: busybox
      target: .
    - affectedResource: ncurses
      target: latest
    - fingerprint: 7820aa24a96f0fcd4717933772a8bc89552a0c1509f3d90b14d885d25e60595f
```

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
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $PWD:/app \
    -e TRAVIS_BUILD_DIR=/app -e REGISTRY_SERVER -e REGISTRY_USERNAME -e REGISTRY_PASSWORD \
    vulcan-local -c /app/vulcan.yaml
```

Start scanning a local http server

```sh
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $PWD/script:/app/script \
    -e REGISTRY_SERVER -e REGISTRY_USERNAME -e REGISTRY_PASSWORD \
    vulcan-local -t http://localhost:1234 -u file:///app/script/checktypes-stable.json
```

Start scanning a local Git repository. **The target path must point to the base of a git repository.**

```sh
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $PWD/script:/app/script -v $PWD:/src \
  -e REGISTRY_SERVER -e REGISTRY_USERNAME -e REGISTRY_PASSWORD \
  vulcan-local -t /src -u file:///app/script/checktypes-stable.json
```
