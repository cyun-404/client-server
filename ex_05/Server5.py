# RSA 알고리즘을 사용해 통신한다.
# 공개키를 만들어 Client에게 전달한다.
# 그 공개키로 암호화된 정보를 수신하고, 복호화시킨다.
# Client에게 제곱값을 반환시켜준다.
# 사용자 인증이 가능하다.
from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from OpenSSL import crypto
from Crypto.Hash import SHA256 as SHA

from OpenSSL.crypto import FILETYPE_PEM, sign, verify, X509


# TCP 연결, 9000포트
port_number = 9000
s = socket(AF_INET,SOCK_STREAM)
s.bind(('127.16.11.2',port_number))
s.listen(1)

# RSA 키
random_generator = Random.new().read
rsa_priv_key = RSA.generate(1024, random_generator)

# 공개키 
# encrypted = (키 정보, None)
rsa_pub_key = rsa_priv_key.publickey()

with open('RSA_pub_key.pem', "wb") as f:
    f.write(rsa_pub_key.exportKey())

cipher = PKCS1_OAEP.new(rsa_priv_key)

# ssl 키 생성
pkey = crypto.PKey()                      
pkey.generate_key(crypto.TYPE_RSA, 1024)                    #RSA 형식의 키 생성

# 공개키, 개인키 생성
with open("public_key.pem",'wb') as f:
    f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, pkey))

with open("private_key.pem",'wb') as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))

# 공개키, 개인키 읽어오기 
with open("private_key.pem",'rb') as f:                                     
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

with open("public_key.pem",'rb') as f:
    pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())


while True:
    trust = False

    # 클라이언트 연결
    clientData,addr = s.accept()
    print('다음 클라이언트가 연결됩니다. ',addr)
    
    # SSL 인증=============================================================

    print('해시 수신 중...')
    compare_hash = clientData.recv(1024)

    # ssl 인증서에 사인
    bob_sign = sign(key, compare_hash, 'sha256')

    print('사인 전달 중...')
    clientData.send(bob_sign)

    # 암호화된 사용자 인증=====================

    print('ID 수신중...')
    user_id = clientData.recv(1024)
    if user_id == 'ssl 인증 실패'.encode():
        print(user_id.decode()+'!!')
        print('다른 클라이언트의 연결을 기다립니다..')
        continue
    
    clientData.send('1'.encode())
    print('PW 수신중...')
    user_pw = clientData.recv(1024)
    clientData.send('1'.encode())

    decoded_id = cipher.decrypt(user_id).decode().rstrip()
    decoded_pass = cipher.decrypt(user_pw).decode().rstrip()

    with open('pw.txt',"r") as f:
        pw_id = f.readline().rstrip()
        pw_pass = f.readline().rstrip()

        if pw_id != decoded_id or pw_pass != decoded_pass:
            clientData.send("인증 실패!".encode())
            print('인증 실패!')
        else:
            clientData.send("인증 성공!".encode())
            print('인증 성공!')
            trust = True

    # 제곱값을 반환하는 서버
    if trust:
        print('값 수신 중..')
        data = clientData.recv(1024)
        if not data:
            break
        decoded_data = cipher.decrypt(data).decode().rstrip()
        pow_number = decoded_data + "의 제곱값은 " \
                    + str(int(decoded_data)*int(decoded_data)) + "입니다."
        print('결과 전송!')
        clientData.sendall(pow_number.encode())
