# RSA 알고리즘을 사용해 통신한다.
# 공개키를 만들어 Client에게 전달한다.
# 그 공개키로 암호화된 정보를 수신하고, 복호화시킨다.
# Client에게 제곱값을 반환시켜준다.
# 사용자 인증이 가능하다.

from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

# TCP 연결, 9000포트
port_number = 9000
s = socket(AF_INET,SOCK_STREAM)
s.bind(('127.16.11.2',port_number))
s.listen(1)

# RSA 키
random_generator = Random.new().read
key = RSA.generate(1024, random_generator)

# 공개키 
# encrypted = (키 정보, None)
pub_key = key.publickey()

with open('public_key.pem', "wb") as f:
    f.write(pub_key.exportKey())

while True:
    trust = False

    cipher = PKCS1_OAEP.new(key)
    # 클라이언트 연결
    clientData,addr = s.accept()
    print('다음 클라이언트가 연결됩니다. ',addr)
    
    # 암호화된 사용자 인증
    user_id = clientData.recv(1024)
    user_pw = clientData.recv(1024)

    decoded_id = cipher.decrypt(user_id).decode().rstrip()
    decoded_pass = cipher.decrypt(user_pw).decode().rstrip()

    with open('pw.txt',"r") as f:
        pw_id = f.readline().rstrip()
        pw_pass = f.readline().rstrip()

        if pw_id != decoded_id or pw_pass != decoded_pass:
            clientData.send("인증 실패!".encode())
        else:
            clientData.send("인증 성공!".encode())
            trust = True

    # 제곱값을 반환하는 서버
    while trust:
        data = clientData.recv(1024)
        if not data:
            break
        decoded_data = cipher.decrypt(data).decode().rstrip()
        pow_number = decoded_data + "의 제곱값은 " \
                    + str(int(decoded_data)*int(decoded_data)) + "입니다."
        clientData.sendall(pow_number.encode())
