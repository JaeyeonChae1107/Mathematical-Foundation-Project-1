#!/usr/bin/env python3
import socket, json, argparse, random, base64, logging
from Crypto.Cipher import AES

# ---- Robust line-based JSON I/O ----
def send_json(s, obj):
    data = json.dumps(obj, separators=(",", ":")) + "\n"  # 라인 단위 프로토콜
    s.sendall(data.encode("ascii"))

def recv_json(s, timeout=10.0):
    s.settimeout(timeout)
    buf = bytearray()
    while True:
        chunk = s.recv(4096)
        if not chunk:
            # EOF인데 아직 개행을 못 봤다면 서버가 비정상 종료한 상황.
            if not buf:
                raise ConnectionError("Connection closed by peer before any data.")
            break
        buf.extend(chunk)
        if b"\n" in buf:
            break

    # 첫 개행까지 한 줄만 파싱 (여분 바이트는 다음 recv에서 서버가 다시 보내므로 무시)
    try:
        line, _ = bytes(buf).split(b"\n", 1)
    except ValueError:
        line = bytes(buf)
    line = line.strip(b"\r\n")
    if not line:
        raise ValueError("Empty line received.")
    return json.loads(line.decode("ascii"))

# ---- Math utils ----
def is_prime(n: int) -> bool:
    if n < 2: return False
    if n % 2 == 0: return n == 2
    f, r = 3, int(n**0.5)
    while f <= r:
        if n % f == 0: return False
        f += 2
    return True

def factorize_distinct(n: int):
    fac = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            fac.append(d)
            n //= d
        d += 1 if d == 2 else 2
    if n > 1: fac.append(n)
    return sorted(set(fac))

def is_generator(g: int, p: int) -> bool:
    if not is_prime(p): return False
    phi = p - 1
    for q in factorize_distinct(phi):
        if pow(g, phi // q, p) == 1:
            return False
    return True

# ---- AES helpers (ECB + PKCS#7) ----
def derive_aes(secret: int) -> bytes:
    # DH 공유비밀을 2바이트 big-endian으로 만들고(0 패딩 포함), 32바이트가 되도록 반복
    b2 = secret.to_bytes(2, "big", signed=False)
    return (b2 * 16)[:32]

def aes_enc_b64(msg: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    pt = msg.encode("utf-8")
    pad = 16 - (len(pt) % 16)
    ct = cipher.encrypt(pt + bytes([pad]) * pad)
    return base64.b64encode(ct).decode("ascii")

def aes_dec_b64(b64: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    ct = base64.b64decode(b64.encode("ascii"))
    pt = cipher.decrypt(ct)
    if not pt:
        return ""
    pad = pt[-1]
    if pad < 1 or pad > 16:
        # 패딩이 이상해도 errors="ignore" 유사 동작: 가능한 만큼 디코드
        return pt.decode("utf-8", errors="ignore")
    return pt[:-pad].decode("utf-8", errors="ignore")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", required=True)
    ap.add_argument("-p", "--port", type=int, required=True)
    ap.add_argument("-l", "--log", default="INFO")
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO),
                        format="%(message)s")

    # 연결 및 초기 핸드셰이크
    s = socket.create_connection((args.addr, args.port), timeout=10.0)
    logging.info("[Alice P3] Connected to %s:%d", args.addr, args.port)

    send_json(s, {"opcode": 0, "type": "DH"})
    msg = recv_json(s)

    # 방어적 파싱
    try:
        p = int(msg["parameter"]["p"])
        g = int(msg["parameter"]["g"])
        B = int(msg["public"])
    except Exception as e:
        raise ValueError(f"Malformed server message: {msg}") from e

    logging.info(f"[Alice P3] From Bob → p={p}, g={g}, B={B}")

    # 파라미터 검증
    if not is_prime(p):
        send_json(s, {"opcode": 3, "error": "incorrect prime number"})
        s.close()
        return
    if not is_generator(g, p):
        send_json(s, {"opcode": 3, "error": "incorrect generator"})
        s.close()
        return

    # 키쌍 생성 및 전송
    a = random.randint(2, p - 2)
    A = pow(g, a, p)
    logging.info(f"[Alice P3] Private a={a}")
    logging.info(f"[Alice P3] Public A=g^a mod p={A}")
    send_json(s, {"opcode": 1, "type": "DH", "public": A})

    # 공유 비밀 및 AES 키 도출
    secret = pow(B, a, p)
    key = derive_aes(secret)
    logging.info(f"[Alice P3] Shared secret K=B^a mod p={secret}")
    logging.info(f"[Alice P3] Derived AES key len={len(key)}")

    # 메시지 교환
    enc = aes_enc_b64("hello", key)
    send_json(s, {"opcode": 2, "type": "AES", "encryption": enc})
    rep = recv_json(s)
    pt = aes_dec_b64(rep.get("encryption", ""), key)
    logging.info(f"[Alice P3] AES decrypted reply: {pt}")

    s.close()

if __name__ == "__main__":
    main()
