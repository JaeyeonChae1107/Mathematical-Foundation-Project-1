import socket, argparse, json, base64, logging, time, sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ===== math utils (DH) =====
def modexp(a, e, m):
    return pow(a, e, m)

def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in [2, 3, 5, 7, 11]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def prime_factors(n: int):
    f, d = set(), 2
    while d * d <= n:
        while n % d == 0:
            f.add(d)
            n //= d
        d += 1
    if n > 1:
        f.add(n)
    return f

def is_generator(g: int, p: int) -> bool:
    if not is_probable_prime(p):
        return False
    phi = p - 1
    for q in prime_factors(phi):
        if pow(g, phi // q, p) == 1:
            return False
    return True

# ===== AES utils (ECB-256 + Base64) =====
def pad(msg: str) -> str:
    k = 16 - (len(msg) % 16)
    return msg + chr(k) * k

def unpad(msg: str) -> str:
    return msg[:-ord(msg[-1])]

def aes_encrypt(key: bytes, plaintext: str) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(ct).decode()

def aes_decrypt(key: bytes, b64_ct: str) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(base64.b64decode(b64_ct))
    return unpad(pt.decode(errors="ignore"))

# ===== net utils =====
def send_json(sock: socket.socket, obj: dict):
    msg = json.dumps(obj).encode()
    sock.send(msg)
    logging.debug(f"[SEND] {obj}")

def recv_json(sock: socket.socket, timeout: float = 8.0):
    sock.settimeout(timeout)
    try:
        raw = sock.recv(8192)
    except socket.timeout:
        logging.debug("recv_json: timeout waiting for data.")
        return None
    if not raw:
        logging.debug("recv_json: empty socket.")
        return None
    txt = raw.decode().strip()
    logging.debug(f"[RECV raw] {txt!r}")
    try:
        return json.loads(txt)
    except Exception as e:
        logging.error(f"[RECV] JSON decode error: {e}")
        return None

# ===== main flow (Protocol III + IV) =====
def run(addr: str, port: int, message: str):
    s = socket.socket()
    s.connect((addr, port))
    logging.info(f"Alice connected to {addr}:{port}")

    # 0) start handshake
    send_json(s, {"opcode": 0, "type": "DH"})
    logging.info("Sent DH start request.")
    time.sleep(0.2)

    # 1) receive parameters
    rep = recv_json(s)
    if not rep or rep.get("opcode") != 1 or rep.get("type") != "DH":
        logging.error(f"Unexpected response: {rep}")
        s.close()
        return

    par = rep.get("parameter") or rep.get("parameters")
    if not par:
        logging.error("Missing 'parameter' field in DH response.")
        s.close()
        return

    try:
        p = int(par["p"])
        g = int(par["g"])
        B = int(rep["public"])
    except Exception as e:
        logging.error(f"Invalid parameter types: {e}")
        s.close()
        return

    logging.info(f"Received p={p}, g={g}, B={B}")

    if not (400 <= p <= 500):
        logging.warning("p is out of the recommended range [400,500] (slide note)")

    # 2) check p/g validity
    if not is_probable_prime(p):
        send_json(s, {"opcode": 3, "type": "DH", "error": "incorrect prime number"})
        logging.warning("Sent error: incorrect prime number")
        s.close()
        return
    if not is_generator(g, p):
        send_json(s, {"opcode": 3, "type": "DH", "error": "incorrect generator"})
        logging.warning("Sent error: incorrect generator")
        s.close()
        return

    logging.info("Valid parameters. Proceeding to DH exchange.")

    # 3) generate & send A (int version only)
    a = int.from_bytes(get_random_bytes(2), "big")
    A = modexp(g, a, p)
    time.sleep(0.2)
    send_json(s, {"opcode": 1, "type": "DH", "public": A})
    logging.info(f"Sent DH public key (int). A={A}")

    # 4) receive AES message from Bob
    rep2 = recv_json(s, timeout=8.0)
    if not rep2:
        logging.error("No AES message received from Bob (timeout).")
        s.close()
        return

    if rep2.get("type") != "AES" or "encryption" not in rep2:
        logging.error(f"Invalid AES format or missing 'encryption' key. Full message: {rep2}")
        s.close()
        return

    # 5) derive AES key (2B→repeat*16)
    shared = modexp(B, a, p)
    shared2 = shared.to_bytes(2, byteorder="big")
    aes_key = shared2 * 16
    logging.info(f"Derived AES-256 key (2B×16). shared={shared}")

    # 6) decrypt Bob's AES message
    try:
        plaintext = aes_decrypt(aes_key, rep2["encryption"])
        print(f"[Alice] Received and decrypted message: {plaintext}")
    except Exception as e:
        logging.error(f"AES decrypt failed: {e}")
        s.close()
        return

    # 7) send reply
    enc_b64 = aes_encrypt(aes_key, message)
    send_json(s, {"opcode": 2, "type": "AES", "encryption": enc_b64})
    logging.info("Sent AES-encrypted response.")

    s.close()

# ===== entry =====
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", required=True, help="Bob server address")
    ap.add_argument("-p", "--port", type=int, required=True, help="Bob server port")
    ap.add_argument("-m", "--msg", type=str, default=None, help="Message to send back to Bob")
    ap.add_argument("-l", "--log", default="INFO")
    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log.upper()),
        format="%(asctime)s %(levelname)s:%(message)s",
        datefmt="%H:%M:%S",
    )

    if args.msg is None:
        try:
            args.msg = input("Enter a message to send back to Bob: ").strip()
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(1)
        if not args.msg:
            args.msg = "hello"

    run(args.addr, args.port, args.msg)
