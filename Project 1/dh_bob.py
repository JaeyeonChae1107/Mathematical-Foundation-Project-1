try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES

OP_START, OP_KEYEX, OP_DATA, OP_ERROR = 0, 1, 2, 3

def send_json(sock, obj): sock.sendall((json.dumps(obj)+"\n").encode("utf-8"))
def recv_json(sock):
    f = sock.makefile("r", encoding="utf-8", newline="\n")
    line = f.readline()
    return json.loads(line.strip()) if line else None

def is_prime(n:int)->bool:
    if n<2: return False
    i=2
    while i*i<=n:
        if n%i==0: return False
        i+=1
    return True

def factorize(n:int):
    s,setn=set(),n
    d=2
    while d*d<=setn:
        if setn%d==0:
            s.add(d)
            while setn%d==0: setn//=d
        d+=1
    if setn>1: s.add(setn)
    return s

def is_generator(g:int,p:int)->bool:
    if not is_prime(p): return False
    phi=p-1
    for q in factorize(phi):
        if pow(g, phi//q, p)==1: return False
    return True

def prime_in_range(lo=400,hi=500):
    while True:
        p=random.randint(lo,hi)
        if is_prime(p): return p

def dh_keypair(p:int,g:int)->Tuple[int,int]:
    priv=random.randint(2,p-2)
    pub=pow(g,priv,p)
    return priv,pub

def shared_secret(pub_other:int, priv:int, p:int)->int:
    return pow(pub_other, priv, p)

def derive_key(K:int)->bytes:
    k2=K.to_bytes(2,"big")
    return k2*16  # 32 bytes

def pad16(s:str)->bytes:
    pad=(16-(len(s)%16))%16
    return (s+" "*pad).encode()

def enc_b64(msg:str,key:bytes)->str:
    ct=AES.new(key,AES.MODE_ECB).encrypt(pad16(msg))
    return base64.b64encode(ct).decode()

def dec_b64(b64:str,key:bytes)->str:
    pt=AES.new(key,AES.MODE_ECB).decrypt(base64.b64decode(b64)).decode()
    return pt.rstrip()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--port",type=int,default=5555)
    args=ap.parse_args()

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", args.port))
        srv.listen(1)
        print(f"[Bob] Listening on 0.0.0.0:{args.port}")
        conn,addr=srv.accept()
        with conn:
            print(f"[Bob] Connected from {addr}")
            m=recv_json(conn)
            if not m or m.get("opcode")!=OP_START or m.get("type")!="DH":
                send_json(conn, {"opcode":OP_ERROR,"error":"invalid start"}); return
            # choose p,g (p prime in [400,500], g generator)
            p=prime_in_range(400,500)
            while True:
                g=random.randint(2,p-2)
                if is_generator(g,p): break
            b_priv,B_pub=dh_keypair(p,g)
            send_json(conn, {"opcode":OP_KEYEX,"type":"DH","public":B_pub,"parameter":{"p":p,"g":g}})
            m=recv_json(conn)
            if not m or m.get("opcode")!=OP_KEYEX or m.get("type")!="DH":
                send_json(conn, {"opcode":OP_ERROR,"error":"invalid keyex from alice"}); return
            A_pub=m.get("public")
            if not isinstance(A_pub,int):
                send_json(conn, {"opcode":OP_ERROR,"error":"invalid public key"}); return
            K=shared_secret(A_pub,b_priv,p)
            key=derive_key(K)
            c1=enc_b64("hello",key)
            send_json(conn, {"opcode":OP_DATA,"type":"AES","encryption":c1})
            m=recv_json(conn)
            if not m or m.get("opcode")!=OP_DATA or m.get("type")!="AES":
                send_json(conn, {"opcode":OP_ERROR,"error":"invalid data from alice"}); return
            plain=dec_b64(m.get("encryption"),key)
            print(f"[Bob] Decrypted from Alice: '{plain}'")
            print("[Bob] Done.")

if __name__=="__main__":
    main()