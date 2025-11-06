import socket
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



def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info(f"Alice connected to {addr}:{port}")

    # Bob에게 RSA 키 요청
    msg = {"opcode": 0, "type": "RSAKey"}
    conn.send(json.dumps(msg).encode())
    logging.info("[>] Sent RSA key request to Bob")

    # Bob의 응답 수신
    data = conn.recv(4096).decode()
    reply = json.loads(data)
    logging.info(f"[<] Received reply from Bob: {reply}")

    p = reply["parameter"]["p"]
    q = reply["parameter"]["q"]
    e = reply["public"]
    d = reply["private"]

    print("\n=== RSA Key Exchange Result ===")
    print(f"p = {p}, q = {q}")
    print(f"Public key (e) = {e}")
    print(f"Private key (d) = {d}")

    # 소수성 검증
    if is_prime(p) and is_prime(q):
        print("Verified: Both p and q are prime numbers.")
    else:
        print("Invalid primes detected.")

    conn.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level>", help="Log level", type=str, default="INFO")
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=getattr(logging, args.log.upper()))
    run(args.addr, args.port)


if __name__ == "__main__":
    main()
