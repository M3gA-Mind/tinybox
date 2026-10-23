# Docker egress enforcement

`NativeLinuxDockerEgressController` is the opt-in implementation of
`DockerEgressController`. `DockerSandbox` has no controller by default, so an
allowlist remains Unsupported unless a host installs this implementation.

## Setup and enforcement

Before creating a network, the controller requires an explicitly local host,
the rootful Docker Engine socket, Linux Docker, `iptables` and `ip6tables`,
their restore tools, Docker's `DOCKER-USER` forwarding hooks, and a usable
bridge firewall interface. It resolves hostnames once through the injected
resolver, rejects loopback and metadata answers, and retains every pinned
address. Docker-assigned IPAM subnets are checked before the firewall is
installed; any pinned address inside one causes the whole setup to roll back.

The controller installs a per-box bridge and default-drop input and forwarding
chains before Docker starts the workload. Pinned TCP destination addresses and
ports are accepted in `DOCKER-USER`; new host-bound traffic is dropped. The
input chain permits required IPv6 Neighbor Solicitation and established
replies. Docker receives static `/etc/hosts` mappings for approved names and a
loopback-only resolver, so its embedded resolver cannot forward arbitrary
queries. Firewall rules also block loopback and the known metadata endpoints.

Each firewall chain and its cryptographic owner marker are created in a single
`iptables-restore --noflush` table transaction. This avoids leaving a chain
without a marker if the process exits between separate commands. Cleanup first
verifies the network labels and all existing chain markers, then removes only
the hooks, chains, and network owned by this box. If verification or cleanup
fails, the caller retains the box record so cleanup can be retried.

## Public surface and limits

- `DockerEgressController` is the lifecycle interface consumed by
  `DockerSandbox`.
- `PreparedEgressNetwork` carries the Docker network name and pinned host
  mappings used in the workload's Docker arguments.
- `NativeLinuxDockerEgressController::new` accepts the resolver used to build
  the pinned plan.

Docker Desktop, remote or unknown daemons, rootless Docker, Windows, macOS, and
hosts without the required firewall or restore capability are refused. The
controller filters TCP egress only; this is not a general-purpose firewall or
a claim that DNS answers are monitored after the one-time plan is created.
The real firewall proof runs only in the disposable hosted Ubuntu Docker job.
