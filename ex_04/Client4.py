# RSA 알고리즘으로 암호화하여 정보를 주고 받는다.
# 서버에 정수를 전달한다.
# 사용자 인증이 가능하다.
from socket import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# block size = 8
def pad(text):
    while len(text) % 8 != 0:
        text += ' '.encode()
    return text

# TCP 연결
s = socket(AF_INET, SOCK_STREAM)
port_number, ip_address = 9000, '127.16.11.2'

if not s.connect((ip_address, port_number)):
    # pem 파일에 저장되어 있는 공개키
    with open('public_key.pem',"rb") as f:
        pub_key = RSA.importKey(f.read())
    cipher = PKCS1_OAEP.new(pub_key)

    # 사용자 인증
    print("---------------------")
    user_id = input("ID : ")
    padded_id = pad(user_id.encode())
    encrypted_id = cipher.encrypt(padded_id)
    s.send(encrypted_id)

    user_pw = input("PW : ")
    padded_pw = pad(user_pw.encode())
    encrypted_pw = cipher.encrypt(padded_pw)
    s.send(encrypted_pw)
    print("---------------------")

    server_message = s.recv(1024)
    print(server_message.decode())

if server_message.decode() == '인증 실패!':
    exit()

#전달할 정수
message= input("제곱할 정수 : ")
padded_m = pad(message.encode())
encrypted_m = cipher.encrypt(padded_m)

# 서버에 정수 값을 전달
s.sendall(encrypted_m)
print(s.recv(1000).decode())
