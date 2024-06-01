# Incus-DNS

Incus-DNS is an asynchronous DNS server and watcher for incus daemon, implemented in Python. It listens
for events from incus, updates DNS records dynamically, and serves DNS queries using UDP.

## Features

- **Dynamic DNS Records**: Automatically updates DNS records.
- **Asynchronous Event Handling**: Utilizes `aiohttp` and `aiomisc` for handling events and network
  operations asynchronously.
- **Configurable Network Filtering**: Filters IP addresses based on configurable network prefixes.
- **Logging**: Supports structured logging with different log levels and formats.

## Installation

### From pypi

```shell
pip install incus-dns
```

### From repository

```shell
git clone https://github.com/mosquito/incus-dns.git
cd incus-dns
poetry install
```

## Configuration

Incus-DNS can be configured using command-line arguments, environment variables, and configuration files.
By default, it looks for configuration files in the following locations:
- `incus-dns.ini` (in the current directory)
- `~/.config/incus-dns/config.ini`
- `/etc/incus-dns.ini`

### Example Configuration File

```ini
[log]
level = INFO
format = plain

[dns]
bind = 127.0.0.53:5353

[DEFAULT]
url = unix:///var/lib/incus/unix.socket
domain = incus
prefix_filter = [
    "2000::/3",
    "1.0.0.0/8",
    ...
]
```

## Usage

### Command-Line Arguments

```sh
incus-dns --domain incus
```

### Environment Variables

You can also set environment variables prefixed with `INCUS_DNS_` to configure the application. For example:

```sh
export INCUS_DNS_LOG_LEVEL=INFO
export INCUS_DNS_DNS_BIND='["127.0.0.53:5353"]'
export INCUS_DNS_URL=unix:///var/lib/incus/unix.socket
export INCUS_DNS_DOMAIN=incus
export INCUS_DNS_PREFIX_FILTER='["2000::/3", "1.0.0.0/8", ...]'
```

### Running the Server

To start the Incus-DNS server, run:

```shell
incus-dns
```

## License

This project is licensed under the Apache 2 License. See the `COPYING` file for details.
