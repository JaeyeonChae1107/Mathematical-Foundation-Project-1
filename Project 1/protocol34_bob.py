import socket, json, base64, argparse, random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ===== AES utils =====
def pad(msg):
    return msg + chr(16 - len(msg) % 16) * (16 - len(msg) % 16)

def unpad(msg):
    return msg[:-ord(msg[-1])]

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(ct).decode()

def aes_decrypt(key, b64_ct):
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(base64.b64decode(b64_ct))
    return unpad(pt.decode(errors="ignore"))

def modexp(a, e, m):
    return pow(a, e, m)

# ===== Prime / Generator utilities =====
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

def generate_prime_and_generator():
    """Generate a random prime p (400~500) and valid generator g."""
    while True:
        p = random.randint(400, 500)
        if not is_probable_prime(p):
            continue
        for g in range(2, p - 1):
            if is_generator(g, p):
                return p, g

# ===== Net utils =====
def send_json(sock, obj):
    sock.send(json.dumps(obj).encode())

def recv_json(sock):
    raw = sock.recv(8192)
    if not raw:
        return None
    try:
        return json.loads(raw.decode().strip())
    except:
        return None

# ===== Main =====
def run(port, mode):
    s = socket.socket()
    s.bind(("0.0.0.0", port))
    s.listen(1)
    print(f"[Bob] Listening on port {port} ({mode} mode)...")
    conn, addr = s.accept()
    print(f"[Bob] Connected by {addr}")

    msg = recv_json(conn)
    if not msg or msg.get("opcode") != 0:
        print("[Bob] Invalid start message.")
        conn.close()
        return
    print("[Bob] Received DH start request.")

    # === Step 1: select parameters depending on mode ===
    if mode == "normal":
        p, g = generate_prime_and_generator()
    elif mode == "nonprime":
        p, g = 456, 62
    elif mode == "nongenerator":
        p, g = 457, 456
    else:
        print("[Bob] Invalid mode. Use: normal / nonprime / nongenerator")
        conn.close()
        return

    b = int.from_bytes(get_random_bytes(2), "big")
    B = modexp(g, b, p)

    send_json(conn, {
        "opcode": 1,
        "type": "DH",
        "public": B,
        "parameter": {"p": p, "g": g}
    })
    print(f"[Bob] Sent parameters p={p}, g={g}, B={B}")

    # === Step 2: receive Alice's DH public key ===
    rep = recv_json(conn)
    if not rep or rep.get("opcode") != 1:
        print("[Bob] Invalid or missing DH public key from Alice.")
        conn.close()
        return

    try:
        A = int(rep["public"])
    except:
        print("[Bob] Could not parse Alice's public key.")
        conn.close()
        return

    shared = modexp(A, b, p)
    aes_key = shared.to_bytes(2, "big") * 16
    print(f"[Bob] Shared key derived = {shared}")

    # === Step 3: send AES encrypted message ===
    enc = aes_encrypt(aes_key, "k-pop")
    send_json(conn, {"opcode": 2, "type": "AES", "encryption": enc})
    print("[Bob] Sent AES message to Alice.")

    # === Step 4: receive Alice's AES response ===
    rep2 = recv_json(conn)
    if not rep2 or rep2.get("type") != "AES":
        print("[Bob] No AES response from Alice.")
        conn.close()
        return

    try:
        plain = aes_decrypt(aes_key, rep2["encryption"])
        print(f"[Bob] Decrypted response from Alice: {plain}")
    except Exception as e:
        print(f"[Bob] AES decrypt failed: {e}")

    conn.close()
    print("[Bob] Connection closed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, required=True, help="Port number to listen on")
    parser.add_argument("-m", "--mode", type=str, default="normal",
                        help="Mode: normal / nonprime / nongenerator")
    args = parser.parse_args()
    run(args.port, args.mode)
