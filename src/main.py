import argparse
import binascii
import socket
import struct
import sys
import time


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", required=True, help="The IP and port of the loggers assistant endpoint [10.10.100.254:48899]")
    parser.add_argument("-xs", help="Local source address (optional)")
    parser.add_argument("-xc", default="WIFIKIT-214028-READ", help="WiFi configuration code")
    parser.add_argument("-xat", help="Send AT command instead of credentials")
    parser.add_argument("-xmb", help="Send Modbus read register instead of credentials (e.g. 00120001)")
    parser.add_argument("-xmbw", help="Send Modbus write register instead of credentials (e.g. 00280001020064)")
    parser.add_argument("-xv", action="store_true", help="Verbose output")
    return parser.parse_args()


def send(sock, addr, message, pause=1, timeout=5, expect_response=True, verbose=False):
    if verbose:
        print(f"> {message.strip()}")
    sock.sendto(message.encode(), addr)
    time.sleep(pause)

    if expect_response:
        sock.settimeout(timeout)
        try:
            data, _ = sock.recvfrom(1500)
            response = data.decode().strip()
            if verbose:
                print(f"< {response}")
            return response
        except socket.timeout:
            print("Timeout waiting for response")
            sys.exit(1)
    return None


def remove_at_ok(resp):
    return resp.replace("+ok=", "", 1)


def modbus_crc(data: bytes) -> bytes:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack('<H', crc)


def modbus_handler(sock, addr, prefix, cmd, verbose=False):
    data = binascii.unhexlify(cmd)
    crc = modbus_crc(data)
    full = data + crc
    msg = f"AT+INVDATA={len(full)},{binascii.hexlify(full).decode()}\n"
    resp = send(sock, addr, msg, verbose=verbose)
    cleaned = resp.replace(chr(0x10), "")
    print(cleaned)


def at_command_handler(sock, addr, cmd, verbose=False):
    resp = send(sock, addr, f"{cmd}\n", verbose=verbose)
    print(resp)


def credentials_handler(sock, addr, verbose=False):
    ap_ssid = send(sock, addr, "AT+WAP\n", verbose=verbose)
    ap_enc = send(sock, addr, "AT+WAKEY\n", verbose=verbose)
    sta_ssid = send(sock, addr, "AT+WSSSID\n", verbose=verbose)
    sta_key = send(sock, addr, "AT+WSKEY\n", verbose=verbose)
    sta_ip = send(sock, addr, "AT+WANN\n", verbose=verbose)
    web_user = send(sock, addr, "AT+WEBU\n", verbose=verbose)

    print("AP settings")
    print(f"\tMode, SSID and Channel:  {remove_at_ok(ap_ssid)}")
    print(f"\tEncryption:              {remove_at_ok(ap_enc)}")
    print("Station settings")
    print(f"\tSSID:                    {remove_at_ok(sta_ssid)}")
    print(f"\tKey:                     {remove_at_ok(sta_key)}")
    print(f"\tIP:                      {remove_at_ok(sta_ip)}")
    print("Web settings")
    print(f"\tLogin:                   {remove_at_ok(web_user)}")


def main():
    args = parse_args()

    if sum(map(bool, [args.xat, args.xmb, args.xmbw])) > 1:
        print("You can't use xat, xmb or xmbw at the same time")
        sys.exit(1)

    ip, port = args.t.split(":")
    addr = (ip, int(port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.xs:
        sock.bind((args.xs, 0))

    print(f"* Connecting to {addr}...")

    response = send(sock, addr, args.xc, verbose=args.xv)
    if not response:
        print("Empty response from logger")
        sys.exit(1)

    send(sock, addr, "+ok", expect_response=False)

    if args.xat:
        at_command_handler(sock, addr, args.xat, verbose=args.xv)
    elif args.xmb:
        if len(args.xmb) != 8:
            print("xmb requires 8 hex chars: e.g. 00120001")
            sys.exit(1)
        modbus_handler(sock, addr, "0103", "0103" + args.xmb, verbose=args.xv)
    elif args.xmbw:
        if len(args.xmbw) < 14:
            print("xmbw requires minimum 14 hex chars: e.g. 00280001020064")
            sys.exit(1)
        modbus_handler(sock, addr, "0110", "0110" + args.xmbw, verbose=args.xv)
    else:
        credentials_handler(sock, addr, verbose=args.xv)

    send(sock, addr, "AT+Q\n", expect_response=False)
    print()


if __name__ == "__main__":
    main()

