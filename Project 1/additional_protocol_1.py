import argparse, json, base64

def pad(msg: str) -> str:
    pad_len = 16 - (len(msg) % 16)
    return msg + chr(pad_len) * pad_len

def unpad(msg: str) -> str:
    return msg[:-ord(msg[-1])]

def aes_decrypt(key: bytes, ciphertext_b64: str) -> str:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    pt_bytes = cipher.decrypt(base64.b64decode(ciphertext_b64))
    return unpad(pt_bytes.decode(errors="ignore"))

def factor_n(n: int):
    f = 2
    while f * f <= n:
        if n % f == 0:
            return f, n // f
        f += 1
    raise ValueError("n factorization failed (n may be prime?)")

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def invmod(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse for e mod phi")
    return x % m

def parse_log(path: str):
    e = n = None
    enc_key_list = None
    ciphertexts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            t, op = obj.get("type"), obj.get("opcode")
            if t == "RSA" and op == 1:
                e = obj["public"]
                n = obj["parameter"]["n"]
            elif t == "RSA" and op == 2 and "encrypted_key" in obj:
                enc_key_list = obj["encrypted_key"]
            elif t == "AES" and op == 2 and "encryption" in obj:
                ciphertexts.append(obj["encryption"])
    if e is None or n is None or enc_key_list is None or not ciphertexts:
        raise ValueError("missing required fields in log")
    return e, n, enc_key_list, ciphertexts

def main():
    ap = argparse.ArgumentParser(description="Protocol II offline decryptor (Alice/Bob style)")
    ap.add_argument("-f", "--file", required=True, help="path to adv_protocol_two-*.log")
    args = ap.parse_args()

    e, n, enc_key_list, cts = parse_log(args.file)

    p, q = factor_n(n)
    phi = (p - 1) * (q - 1)
    d = invmod(e, phi)

    key_bytes = bytearray()
    for c in enc_key_list:
        m = pow(c, d, n)       
        key_bytes.append(m)       
    key = bytes(key_bytes)
    if len(key) != 32:
        raise ValueError(f"AES key must be 32 bytes, got {len(key)}")

    print(f"[info] n={n} = {p}×{q}, e={e}, d={d}")
    print(f"[info] AES-256 key (hex): {key.hex()}")

    for i, ct in enumerate(cts, 1):
        try:
            pt = aes_decrypt(key, ct)
            print(f"[{i}] {pt}")
        except Exception as ex:
            print(f"[{i}] <decrypt error> {ex}")

if __name__ == "__main__":
    main()