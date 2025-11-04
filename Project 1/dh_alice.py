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

def dh_keypair(p:int,g:int)->Tuple[int,int]:
    priv=random.randint(2,p-2)
    pub=pow(g,priv,p)
    return priv,pub

def shared_secret(pub_other:int, priv:int, p:int)->int:
    return pow(pub_other, priv, p)

def derive_key(K:int)->bytes:
    k2=K.to_bytes(2,"big")
    return k2*16

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
    ap.add_argument("--addr",default="127.0.0.1")
    ap.add_argument("--port",type=int,default=5555)
    args=ap.parse_args()

    with socket.create_connection((args.addr, args.port)) as sock:
        send_json(sock, {"opcode":OP_START,"type":"DH"})
        m=recv_json(sock)
        if not m or m.get("opcode")!=OP_KEYEX or m.get("type")!="DH":
            print("[Alice] invalid keyex from bob"); return
        params=m.get("parameter") or {}
        p=params.get("p"); g=params.get("g"); B_pub=m.get("public")
        # validate p,g
        if not (isinstance(p,int) and is_prime(p)):
            send_json(sock, {"opcode":OP_ERROR,"error":"incorrect prime number"}); return
        if not (isinstance(g,int) and is_generator(g,p)):
            send_json(sock, {"opcode":OP_ERROR,"error":"incorrect generator"}); return
        a_priv,A_pub=dh_keypair(p,g)
        send_json(sock, {"opcode":OP_KEYEX,"type":"DH","public":A_pub})
        K=shared_secret(B_pub,a_priv,p)
        key=derive_key(K)
        m=recv_json(sock)
        if not m or m.get("opcode")!=OP_DATA or m.get("type")!="AES":
            print("[Alice] invalid data from bob"); return
        plain=dec_b64(m.get("encryption"),key)
        print(f"[Alice] Decrypted from Bob: '{plain}'")
        c2=enc_b64("world",key)
        send_json(sock, {"opcode":OP_DATA,"type":"AES","encryption":c2})
        print("[Alice] Done.")

if __name__=="__main__":
    main()