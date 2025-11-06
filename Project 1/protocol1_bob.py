import socket
import threading
import argparse
import logging
import json
import random


def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True



def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Python 3.7용 확장 유클리드 알고리즘 기반 modular inverse"""
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise Exception("No modular inverse")
    return x % phi


def generate_rsa_keys():
    primes = [p for p in range(400, 501) if is_prime(p)]
    e = 65537

    while True:
        p, q = random.sample(primes, 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) == 1:
            d = mod_inverse(e, phi)
            logging.info(f"Generated RSA keys: p={p}, q={q}, n={n}")
            return {"p": p, "q": q, "n": n, "e": e, "d": d}
        else:
            logging.warning(f"Invalid pair skipped: p={p}, q={q}, gcd={gcd(e, phi)}")
            continue



def handler(sock):
    try:
        data = sock.recv(4096).decode()
        if not data:
            logging.warning("Received empty data from Alice.")
            return

        msg = json.loads(data)
        logging.info(f"[*] Received message from Alice: {msg}")

        if msg.get("opcode") == 0 and msg.get("type") == "RSAKey":
            rsa = generate_rsa_keys()
            reply = {
                "opcode": 0,
                "type": "RSAKey",
                "public": rsa["e"],
                "private": rsa["d"],
                "parameter": {"p": rsa["p"], "q": rsa["q"], "n": rsa["n"]},
            }
            sock.sendall(json.dumps(reply).encode())
            logging.info("[+] Sent RSA key pair to Alice.")

    except Exception as e:
        logging.error(f"Error in handler: {e}")
    finally:
        sock.close()


def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info(f"[*] Bob is listening on {addr}:{port}")

    while True:
        conn, info = bob.accept()
        logging.info(f"[*] Bob accepts connection from {info[0]}:{info[1]}")
        threading.Thread(target=handler, args=(conn,)).start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", default="0.0.0.0", help="Bob's IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Bob's open port")
    parser.add_argument("-l", "--log", default="INFO", help="Log level (DEBUG/INFO/...)")
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=getattr(logging, args.log.upper()))
    run(args.addr, args.port)


if __name__ == "__main__":
    main()
