# openssl을 통해 Server가 Bob임이 증명되어야 정보를 내어준다.
# RSA 알고리즘으로 암호화하여 정보를 주고 받는다.
# 서버에 정수를 전달한다.
# 사용자 인증이 가능하다.
from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from OpenSSL import crypto
from Crypto.Hash import SHA256 as SHA

from OpenSSL.crypto import FILETYPE_PEM, sign, verify, X509

# block size = 8
def pad(text):
    while len(text) % 8 != 0:
        text += ' '.encode()
    return text

# TCP 연결
s = socket(AF_INET, SOCK_STREAM)
port_number, ip_address = 9000, '127.16.11.2'

if not s.connect((ip_address, port_number)):
    #SSl 인증========================================================
    # 인증을 위한 공개키
    with open('public_key.pem',"rb") as f:
        pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())

    compare_hash = SHA.new('message_'.encode('utf-8')).digest()
    # 전달받은 인증서
    print('비교할 해시 전달 중...')
    s.send(compare_hash)
    print('인증 사인 수신 중...')
    bob_sign = s.recv(1024)
    print('해시 수신 완료!')
    print('x509 설정 중..')
    x509 = X509()
    x509.set_pubkey(pub_key)

    # Bob에 대한 인증
    try :
        verify(x509, bob_sign, compare_hash , 'sha256')
        print('SSL 인증!!')
        trust = True
    except :
        print('변조된 사인!!')
        trust = False

    #SSL 인증=================================================================

    if trust:
        with open('RSA_pub_key.pem', "rb") as f:
            pub_key = RSA.importKey(f.read())
        cipher = PKCS1_OAEP.new(pub_key)


        # 사용자 인증
        print("---------------------")
        user_id = input("ID : ")
        padded_id = pad(user_id.encode())
        encrypted_id = cipher.encrypt(padded_id)
        s.send(encrypted_id)
        s.recv(1024)

        user_pw = input("PW : ")
        padded_pw = pad(user_pw.encode())
        encrypted_pw = cipher.encrypt(padded_pw)
        s.send(encrypted_pw)
        s.recv(1024)
        print("------------------------")

        server_message = s.recv(1024)
        print(server_message.decode())

        if server_message.decode() == '인증 실패!':
            exit()

        #전달할 정수
        message= input("제곱할 정수 : ")
        padded_m = pad(message.encode())
        encrypted_m = cipher.encrypt(padded_m)

        # 서버에 정수 값을 전달
        print('값 전송 중...')
        s.sendall(encrypted_m)
        print(s.recv(1000).decode())
    else:
        s.send('ssl 인증 실패'.encode())
