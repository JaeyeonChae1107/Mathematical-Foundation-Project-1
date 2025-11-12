import socket
import argparse
import logging
import json
import random

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def run(addr, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((addr, port))
    logging.info(f"Alice connected to {addr}:{port}")

    try:
        
        req = {"opcode": 0, "type": "RSAKey"}
        sock.sendall(json.dumps(req).encode())
        logging.info("[>] Sent RSA key request to Bob")

        
        data = sock.recv(8192).decode()
        if not data:
            logging.error("No data received from Bob.")
            return

        try:
            reply = json.loads(data)
        except json.JSONDecodeError:
            logging.error("Invalid JSON from Bob: %r", data)
            return

        logging.info(f"[<] Received reply from Bob: {reply}")

        try:
            p = int(reply["parameter"]["p"])
            q = int(reply["parameter"]["q"])
            e = int(reply["public"])
            d = int(reply["private"])
        except (KeyError, TypeError, ValueError) as ex:
            logging.error(f"Missing or invalid fields in Bob's reply: {ex}")
            return

        n = p * q
        phi = (p - 1) * (q - 1)

        checks = []
        checks.append(("p in [400,500]", 400 <= p <= 500))
        checks.append(("q in [400,500]", 400 <= q <= 500))
        checks.append((f"p={p} is prime", is_prime(p)))
        checks.append((f"q={q} is prime", is_prime(q)))
        checks.append(("gcd(e, phi) == 1", gcd(e, phi) == 1))
        checks.append(("(e*d) % phi == 1", (e * d) % phi == 1))

        print("\n=== Protocol I — RSA Key & Verification (Alice) ===")
        print(f"p = {p}, q = {q}")
        print(f"n = p*q = {n}")
        print(f"public e = {e}")
        print(f"private d = {d}\n")

        all_ok = True
        for name, ok in checks:
            status = "OK" if ok else "FAIL"
            print(f"[{status}] {name}")
            if not ok:
                all_ok = False


    finally:
        sock.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level>", help="Log level", type=str, default="INFO")
    return parser.parse_args()

def main():
    args = command_line_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))
    run(args.addr, args.port)

if __name__ == "__main__":
    main()
