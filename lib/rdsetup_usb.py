"""Token-gated setup replies over the wired usbmux transport used for SSH."""

import asyncio
import hashlib
import inspect
import re
import struct
from dataclasses import dataclass


PORT = 42420
TOKEN_SIZE = 32
MAGIC = b"DRA1USB1"
HEADER = struct.Struct("!8scII")
MAX_LOG = 64 * 1024
MAX_TICKET = 64 * 1024
RETRY_ERRORS = (OSError, EOFError, asyncio.TimeoutError)


class SetupUSBError(Exception):
    pass


@dataclass(frozen=True)
class Reply:
    state: bytes
    log: bytes
    ticket: bytes = b""
    ticket_dir: str = ""


def require_usbmux():
    try:
        from pymobiledevice3 import usbmux
    except ImportError as error:
        raise SetupUSBError("USB setup requires pymobiledevice3. Run ./setup.sh.") from error
    if not inspect.iscoroutinefunction(getattr(usbmux, "list_devices", None)) or not inspect.iscoroutinefunction(
        getattr(getattr(usbmux, "MuxDevice", None), "connect", None)
    ):
        raise SetupUSBError("USB setup requires the async pymobiledevice3 usbmux API. Run ./setup.sh.")


def matching_usb_device(devices, ecid):
    matches = []
    for device in devices:
        udid = re.fullmatch(r"[0-9a-f]{8}-?([0-9a-f]{16})", device.serial, re.IGNORECASE)
        if device.connection_type == "USB" and udid and udid[1].lower() == ecid:
            matches.append(device)
    if len(matches) > 1:
        raise SetupUSBError(f"More than one USB device matched ECID {ecid}.")
    if not matches:
        raise OSError(f"No USB device with ECID {ecid} is visible yet.")
    return matches[0]


async def connect_usb(ecid):
    from pymobiledevice3 import usbmux
    from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionFailedToUsbmuxdError, MuxException

    try:
        device = matching_usb_device(await usbmux.list_devices(), ecid)
        return await device.connect(PORT)
    except (MuxException, ConnectionFailedError, ConnectionFailedToUsbmuxdError) as error:
        raise OSError("The setup ramdisk's USB service is unavailable.") from error


async def read_exact(sock, size):
    loop = asyncio.get_running_loop()
    data = bytearray()
    while len(data) < size:
        chunk = await loop.sock_recv(sock, size - len(data))
        if not chunk:
            raise EOFError("The setup ramdisk closed the USB connection.")
        data.extend(chunk)
    return bytes(data)


async def request(ecid, token, operation):
    sock = await connect_usb(ecid)
    with sock:
        sock.setblocking(False)
        await asyncio.get_running_loop().sock_sendall(sock, operation + token)
        magic, state, log_size, ticket_size = HEADER.unpack(await read_exact(sock, HEADER.size))
        if magic != MAGIC or state not in (b"R", b"S", b"O", b"E"):
            raise SetupUSBError("Unexpected USB setup response.")
        if log_size > MAX_LOG or ticket_size > MAX_TICKET:
            raise SetupUSBError("USB setup response exceeds the expected size.")
        if (state in (b"R", b"S") and log_size) or (state != b"O" and ticket_size):
            raise SetupUSBError("Unexpected data in the USB setup response.")
        log = await read_exact(sock, log_size)
        if not ticket_size:
            return Reply(state, log)
        directory = await read_exact(sock, 96)
        digest = await read_exact(sock, 48)
        ticket = await read_exact(sock, ticket_size)
        if not re.fullmatch(rb"[0-9a-f]{96}", directory, re.IGNORECASE):
            raise SetupUSBError("Invalid Preboot directory in the USB ticket report.")
        if hashlib.sha384(ticket).digest() != digest:
            raise SetupUSBError("The USB APTicket did not match its SHA-384 digest.")
        return Reply(state, log, ticket, directory.decode("ascii"))


async def poll_result(ecid, token, timeout, *, waiting_for_ready):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while (remaining := deadline - loop.time()) > 0:
        try:
            response = await asyncio.wait_for(request(ecid, token, b"G"), min(3, remaining))
        except RETRY_ERRORS:
            await asyncio.sleep(min(1, max(0, deadline - loop.time())))
            continue
        if waiting_for_ready and response.state == b"R":
            return response
        if not waiting_for_ready and response.state in (b"O", b"E"):
            return response
        if not waiting_for_ready and response.state == b"R":
            raise SetupUSBError("The ramdisk reports it is idle after the USB start request.")
        raise SetupUSBError("The USB setup ramdisk is in an unexpected state.")
    if waiting_for_ready:
        raise SetupUSBError("The setup ramdisk did not answer over USB. Check whether it appears in idevice_id -l.")
    raise SetupUSBError("No USB setup result arrived after the start request. Check the phone's screen before retrying.")


async def get_report(ecid, token, *, probe=False, ready_timeout=90, result_timeout=1800):
    if len(token) != TOKEN_SIZE:
        raise SetupUSBError("The USB setup token has the wrong size.")
    await poll_result(ecid, token, ready_timeout, waiting_for_ready=True)
    if probe:
        return None
    try:
        response = await asyncio.wait_for(request(ecid, token, b"S"), 3)
        if response.state != b"S":
            raise SetupUSBError("The USB setup ramdisk did not acknowledge start.")
    except RETRY_ERRORS:
        # The start request may have reached the device. Only read status after this point.
        pass
    return await poll_result(ecid, token, result_timeout, waiting_for_ready=False)
