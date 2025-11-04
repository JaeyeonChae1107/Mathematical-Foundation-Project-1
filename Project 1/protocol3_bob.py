#!/usr/bin/env python3
import socket, json, argparse, random, base64, logging
from Crypto.Cipher import AES

# ===== Utilities =====
def send_json(conn,obj): conn.sendall((json.dumps(obj)+"\n").encode())
def recv_json(conn):
    buf=b""
    while b"\n" not in buf:
        chunk=conn.recv(4096)
        if not chunk: break
        buf+=chunk
    line,_=buf.split(b"\n",1)
    return json.loads(line.decode())

def is_prime(n):
    if n<2: return False
    if n%2==0: return n==2
    r=int(n**0.5); f=3
    while f<=r:
        if n%f==0: return False
        f+=2
    return True

def factorize(n):
    fac=[]; d=2
    while d*d<=n:
        while n%d==0:
            fac.append(d); n//=d
        d+=1 if d==2 else 2
    if n>1: fac.append(n)
    return list(set(fac))

def is_generator(g,p):
    if not is_prime(p): return False
    phi=p-1
    for q in factorize(phi):
        if pow(g,phi//q,p)==1: return False
    return True

def pick_prime_400_500():
    while True:
        n=random.randint(400,500)
        if is_prime(n): return n

def derive_aes(secret):
    b2 = secret.to_bytes(2,'big'); return (b2*16)[:32]

def aes_enc_b64(msg,key):
    cipher=AES.new(key,AES.MODE_ECB)
    pad=16-(len(msg)%16)
    ct=cipher.encrypt(msg.encode()+bytes([pad])*pad)
    return base64.b64encode(ct).decode()

def aes_dec_b64(b64,key):
    cipher=AES.new(key,AES.MODE_ECB)
    ct=base64.b64decode(b64)
    pt=cipher.decrypt(ct)
    return pt[:-pt[-1]].decode()

# ===== Protocol III =====
def handler(conn,addr):
    logging.info(f"[Bob P3] Connected {addr}")
    try:
        req=recv_json(conn)
        if req.get("opcode")==0 and req.get("type")=="DH":
            # ① p, g 선택
            p=pick_prime_400_500()
            for g in range(2,p):
                if is_generator(g,p): break
            logging.info(f"[Bob P3] Selected prime p={p}, generator g={g}")
            
            # ② Bob의 개인키 b, 공개키 B 생성
            b=random.randint(2,p-2)
            B=pow(g,b,p)
            logging.info(f"[Bob P3] Private key b={b}")
            logging.info(f"[Bob P3] Public key B=g^b mod p={B}")

            # ③ Alice에게 전달
            send_json(conn,{"opcode":1,"type":"DH","public":B,"parameter":{"p":p,"g":g}})
            
            # ④ Alice의 공개키 A 수신
            msg=recv_json(conn)
            A=msg["public"]
            logging.info(f"[Bob P3] Received Alice's public key A={A}")

            # ⑤ 공유 비밀 계산
            secret=pow(A,b,p)
            logging.info(f"[Bob P3] Shared secret (K = A^b mod p) = {secret}")

            # ⑥ AES 키 파생
            key=derive_aes(secret)
            logging.info(f"[Bob P3] Derived AES key (len={len(key)} bytes)")

            # ⑦ AES 통신
            enc=recv_json(conn)
            pt=aes_dec_b64(enc["encryption"],key)
            logging.info(f"[Bob P3] AES decrypted from Alice: {pt}")
            rep=aes_enc_b64("world",key)
            send_json(conn,{"opcode":2,"type":"AES","encryption":rep})
            logging.info("[Bob P3] Sent AES reply to Alice.")
    except Exception as e:
        logging.error(e)
    finally:
        conn.close()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("-a","--addr",default="0.0.0.0")
    ap.add_argument("-p","--port",type=int,required=True)
    ap.add_argument("-l","--log",default="INFO")
    args=ap.parse_args()
    logging.basicConfig(level=getattr(logging,args.log.upper(),logging.INFO),format="%(message)s")
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind((args.addr,args.port)); s.listen(5)
    logging.info(f"[Bob P3] Listening on {args.addr}:{args.port}")
    while True:
        c,a=s.accept()
        handler(c,a)

if __name__=="__main__":
    main()
