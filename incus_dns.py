import asyncio
import json
import logging
from ipaddress import (
    IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_interface,
    ip_network,
)
from multiprocessing import cpu_count
from typing import AbstractSet, Any, Dict, FrozenSet, List, Set, Union

import aiohttp
import aiomisc
import argclass
from aiochannel import Channel
from aiomisc import Service, asyncretry
from aiomisc.service.sdwatchdog import SDWatchdogService
from aiomisc.service.udp import UDPServer
from aiomisc_log import LogFormat, LogLevel
import dnslib
from yarl import URL


log = logging.getLogger(__name__)


NetworkType = Union[IPv4Network, IPv6Network]
AddressType = Union[IPv4Address, IPv6Address]


NETWORK_FILTER_DEFAULT = json.dumps([
    # All global IPv6 addresses
    "2000::/3",
    # All global IPv4 addresses
    "1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4",
    "20.0.0.0/6", "24.0.0.0/8", "25.0.0.0/8", "26.0.0.0/7", "28.0.0.0/7", "30.0.0.0/8", "31.0.0.0/8",
    "32.0.0.0/8", "33.0.0.0/8", "34.0.0.0/7", "36.0.0.0/7", "38.0.0.0/7", "40.0.0.0/6", "44.0.0.0/7",
    "46.0.0.0/8", "47.0.0.0/8", "49.0.0.0/8", "50.0.0.0/7", "52.0.0.0/6", "56.0.0.0/7", "58.0.0.0/7",
    "60.0.0.0/6", "62.0.0.0/7", "64.0.0.0/4", "72.0.0.0/5", "80.0.0.0/4", "96.0.0.0/5", "104.0.0.0/5",
    "112.0.0.0/4", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/7", "173.0.0.0/8", "174.0.0.0/7",
    "176.0.0.0/4", "192.0.0.0/8", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/7",
    "202.0.0.0/7", "204.0.0.0/6", "208.0.0.0/4",
])


STORE: Dict[str, AbstractSet[AddressType]] = {}


class LogGroup(argclass.Group):
    level = argclass.Argument(choices=LogLevel.choices(), default=LogLevel.default())
    format = argclass.Argument(choices=LogFormat.choices(), default=LogFormat.default())


class DNSGroup(argclass.Group):
    bind: List[str] = argclass.Argument(
        default=json.dumps(['127.0.0.53:5353']),
        type=str, nargs=argclass.Nargs.ONE_OR_MORE
    )
    ttl: int = 3600


class Parser(argclass.Parser):
    log = LogGroup()
    dns: DNSGroup = DNSGroup()
    pool_size: int = max(min([16, cpu_count()]), 16)
    url: URL = "unix:///var/lib/incus/unix.socket"
    domain: str = "incus"
    prefix_filter: List[NetworkType] = argclass.Argument(
        type=ip_network, default=NETWORK_FILTER_DEFAULT,
        nargs=argclass.Nargs.ONE_OR_MORE,
    )


class DNSServer(UDPServer):
    ttl: int

    async def handle_datagram(self, data: bytes, addr: tuple) -> None:
        global STORE

        record = dnslib.DNSRecord.parse(data)
        question: dnslib.DNSQuestion = record.get_q()
        reply = record.reply()
        query_name = str(question.get_qname())
        addresses: AbstractSet[AddressType] = STORE.get(query_name, frozenset())

        rrs: List[dnslib.RR] = []
        for address in addresses:
            if address.version == 4 and question.qtype == dnslib.QTYPE.A:
                qtype = dnslib.QTYPE.A
                rdata = dnslib.A(str(address))
            elif address.version == 6 and question.qtype == dnslib.QTYPE.AAAA:
                qtype = dnslib.QTYPE.AAAA
                rdata = dnslib.AAAA(str(address))
            else:
                continue
            rrs.append(dnslib.RR(query_name, qtype, ttl=self.ttl, rdata=rdata))

        if rrs:
            reply.add_answer(*rrs)

        self.sendto(reply.pack(), addr)


class IncusClient:
    def __init__(self, server_url: URL):
        headers = {}
        if server_url.scheme == "unix":
            connector = aiohttp.UnixConnector(path=server_url.path)
            base_url = URL("http://incus/")
        else:
            raise NotImplementedError(f"{server_url.scheme} is not supported")

        self.session = aiohttp.ClientSession(
            connector=connector, connector_owner=True, headers=headers, base_url=base_url,
        )

    async def close(self):
        await self.session.close()

    @asyncretry(10, pause=1)
    async def _get_metadata(self, url: Union[URL, str]) -> dict:
        async with self.session.get(url) as response:
            payload = await response.json()
            return payload["metadata"]

    async def list_instances(self):
        return await self._get_metadata("/1.0/instances?recursion=2&all-projects=true")

    async def get_instance_state(self, instance_name: str, project: str) -> dict:
        return await self._get_metadata(URL(f"/1.0/instances/{instance_name}/state").with_query(project=project))

    async def events(self, result_queue: Channel[Any], query_params) -> None:
        try:
            while True:
                try:
                    async with self.session.ws_connect(URL("/1.0/events").with_query(query_params)) as ws:
                        message: aiohttp.WSMessage

                        async for message in ws:
                            log.debug("Handling message: %s", message)
                            try:
                                await result_queue.put(message.json())
                            except (ValueError, TypeError):
                                log.error("Unable to parse message: %r", message.data)
                                continue
                except aiohttp.ClientError:
                    log.exception("Event stream unexpectedly closed. Retrying after 1 second.")
                    await asyncio.sleep(1)
        finally:
            result_queue.close()


class TaskStore:
    def __init__(self, *args, **kwargs):
        self.__tasks: Set[asyncio.Task] = set()
        self.__loop = asyncio.get_running_loop()

    def create_task(self, coro) -> asyncio.Task:
        task = self.__loop.create_task(coro)
        self.__tasks.add(task)
        task.add_done_callback(self.__tasks.discard)
        return task

    async def close(self):
        await aiomisc.cancel_tasks(self.__tasks)


class IncusWatcher(Service):
    url: URL
    networks: FrozenSet[NetworkType]
    domain: str

    _incus: IncusClient
    _tasks: TaskStore

    def filter_addresses(self, state: Dict) -> FrozenSet[AddressType]:
        network_state = state.get("network")
        if not network_state:
            raise ValueError("Empty network state")

        addresses: Set[AddressType] = set()
        for interface_name, interface_state in network_state.items():
            global_addresses: List[AddressType] = [
                ip_interface(f"{addr["address"]}/{addr["netmask"]}").ip
                for addr in interface_state["addresses"]
                if addr.get("scope") == "global"
            ]

            matched_addresses: FrozenSet[AddressType] = frozenset([
                addr for addr in global_addresses
                if any(
                    network.version == addr.version and addr in network
                    for network in self.networks
                )
            ])

            if matched_addresses:
                addresses.update(matched_addresses)

        return frozenset(addresses)

    def format_name(self, instance_name: str, project: str) -> str:
        if project == "default":
            return f"{instance_name}.{self.domain}."
        return f"{instance_name}.{instance_name}.{self.domain}."

    @asyncretry(10, exceptions=(ValueError,))
    async def on_instance_started(self, instance_name: str, project: str):
        global STORE

        log.debug(
            "Processing instance created event for instance=%r, project=%r",
            instance_name, project
        )

        # delay before gathering instance state
        await asyncio.sleep(5)

        # noinspection PyBroadException
        state = await self._incus.get_instance_state(instance_name, project)
        log.debug(
            "Gathered state for instance=%r, project=%r: %s",
            instance_name, project, state
        )

        addresses = self.filter_addresses(state)
        name = self.format_name(instance_name, project)
        log.debug("Gathered addresses for name %r is %r", name, addresses)

        if not addresses:
            raise ValueError(f"No addresses found for instance={instance_name} project={project}")
        STORE[name] = addresses

    async def on_instance_deleted(self, instance_name: str, project: str):
        global STORE

        name = self.format_name(instance_name, project)
        STORE.pop(name, None)

    async def process_events(self, channel: Channel[Any]) -> None:
        handlers = {
            "instance-started": self.on_instance_started,
            "instance-deleted": self.on_instance_deleted,
        }

        async for event in channel:
            metadata = event.get("metadata")
            if not metadata:
                log.warning("Blank event: %r", event)
                continue

            action = metadata.get("action")
            project = metadata.get("project")
            name = metadata.get("name")

            if not all([action, project, name]):
                log.warning("Bad event metadata: %s", event)
                continue

            if action not in handlers:
                log.debug("Skipping action: %r", event["metadata"]["action"])
                continue

            self._tasks.create_task(handlers[action](instance_name=name, project=project))

    async def fill_state(self):
        global STORE

        instance_list = await self._incus.list_instances()
        log.info("Found %d instances", len(instance_list))

        for instance in instance_list:
            name = self.format_name(instance["name"], instance["project"])
            try:
                adresses = self.filter_addresses(instance["state"])
            except ValueError:
                continue

            STORE[name] = adresses

    async def start(self) -> Any:
        global STORE
        self._incus = IncusClient(self.url)
        self._tasks = TaskStore()

        channel = Channel()
        self._tasks.create_task(self._incus.events(channel, {"all-projects": 1, "type": "lifecycle"}))
        self._tasks.create_task(self.process_events(channel))
        await self.fill_state()
        log.debug("Store is: %r", STORE)

    async def stop(self, *_) -> None:
        await asyncio.gather(
            self._tasks.close(), self._incus.close(),
            return_exceptions=True,
        )


def main():
    arguments = Parser(
        auto_env_var_prefix="INCUS_DNS_",
        config_files=[
            "incus-dns.ini",
            "~/.config/incus-dns/config.ini",
            "/etc/incus-dns.ini",
        ],
    )
    arguments.parse_args()
    arguments.sanitize_env()

    services = [
        SDWatchdogService(),
        IncusWatcher(
            url=arguments.url,
            networks=frozenset(arguments.prefix_filter),
            domain=arguments.domain,
        ),
    ]

    for bind in arguments.dns.bind:
        if ":" in bind:
            address, str_port = bind.split(":", 1)
            port = int(str_port)
        else:
            address = "::"
            port = int(bind)

        services.append(
            DNSServer(address=address, port=port, ttl=arguments.dns.ttl)
        )

    with aiomisc.entrypoint(
        *services,
        log_level=arguments.log.level,
        log_format=arguments.log.format,
        pool_size=arguments.pool_size,
    ) as loop:
        loop.run_forever()


if __name__ == "__main__":
    main()
