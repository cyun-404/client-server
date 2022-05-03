# client-sever
목차
0. 사전 실습	3
- VeraCrypt설치	3
- AES파일 생성	4
- Dismount 결과	8
1. block 암호법  DES, 3DES, AES 를 프로그래밍 하고 동작을 검증하라.	8
a) 100byte 이상의 text 파일을 대상으로 암호화 하여 저장하고 다시 복호화 하여 확인하라.	12
- DES로 text파일 암호화 복호화	12
- AES, DES, 3DES로 text파일 암호화	14
- 3DES 로 text파일 암호화 복호화	18
- AES로 text파일 암호화 복호화	20
b) 파일을 전송하는 단단한 client-server 프로그램을 작성하고 이를 암호화 하여 전송한후 복호화 하여 확인하라.	26
c) 그림판으로 간단한 도형을 그린후 gif 형식으로 저장한후 이를 ECB, CBC 모드로 암호화한후 암호화된 파일을 보여라.	34
2. 문제1에서 테스트 파일을 사용하여	37
a) md5, sha1 등의 hash 방법으로 hash 코드를 구하는 프로그램을 작성하여 hash 코드를 구하라(hash 방법은 2가지 이상의 표준화된 방법을 사용하라.)	37
[참고자료]	49
첨부파일 소개	50

0. 사전 실습
- VeraCrypt설치
  
 
- AES파일 생성
 
AES Test를 실행해 보았습니다.
   
Enncrpt와 Decrypt를 테스트 해 볼 수 있었습니다.
 
 
 
 
아래와 같이 O디스크가 생성되었으며, 이 디스크안에 test.txt파일을 작성하였습니다.
 
 
- Dismount 결과
 
1. block 암호법  DES, 3DES, AES 를 프로그래밍 하고 동작을 검증하라.
 실습에 앞서 필요한 환경을 구축하기 위해 주피터 노트북의 설치를 확인하였습니다.
 
실행을 하려고 명령어를 입력하여도 주피터 노트북이 동작하지 않아 이 문제를 해결하려고 합니다.
 
 
위의 아나콘다 네비게이터에서의 launch로 주피터 노트북을 실행 할 수 있었습니다.
 
주피터 노트북의 실행을 완료하였습니다.
이제 python코드를 작성하기 위해 폴더에 ipynb파일을 새로 생성합니다.
DES 인코딩, 디코딩 코드를 작성해 보고자 합니다.
 
AES CBC 모드로 암호화/복호화 하는 클래스입니다.
위 라이브러리를 사용하기위해선 파이썬 버전에 맞는 라이브러리를 설치해줘야합니다.
설치를 통해 문제를 해결하였지만 아래와 같은 문제가 발생하였습니다.
 
 
 
Pip을 업그래이드 하였으나 pycrypto가 설치되지 않습니다.
문제를 해결하기 위해 검색한 결과 python버전이 3.x이상이므로 pip install pycryptodomex 를 설치해야 한다고 합니다.
 
 
-	AES 실습
 

   a) 100byte 이상의 text 파일을 대상으로 암호화 하여 저장하고 다시 복호화 하여 확인하라.
- DES로 text파일 암호화 복호화
from Crypto.Cipher import DES

# block size = 8
def pad(text):
    while len(text) % 8 != 0:
        text += ' '.encode()
    return text

# 파일의 text를 인코딩 저장
def encodeText(text_name):
    with open(text_name, "r") as f:
        text = f.read()
        print("plaintext: ", text)

    # 8바이트 단위 묶음
    padded_text = pad(text.encode())
    encrypted_text = des.encrypt(padded_text) 

    with open(text_name, "wb") as f:
        f.write(encrypted_text)
    return encrypted_text

# 파일을 복호화해서 다시 저장
def decodeCrypto(text_name):
    with open(text_name, "rb") as f:
        decrypted_text = des.decrypt(f.read())
    with open(text_name, "wb") as f:
        f.write(decrypted_text)
    return decrypted_text.decode()

key = 'sirichoi'.encode()
des = DES.new(key, DES.MODE_ECB)

text_file = "plain.txt"
encoded_text = encodeText(text_file)
print("DES encrypt :",encoded_text)

decoded_text = decodeCrypto(text_file)
print("decrypt : ", decoded_text)

 
- AES, DES, 3DES로 text파일 암호화 
from Crypto.Cipher import AES,DES,DES3,Blowfish
 
cbytes = lambda x: str.encode(x) if type(x) == str else x

 
'''
AES
iv: 16
key: 16
blocksize: 16
'''
def encrypt_aes(message=None, iv='\x00'*16, key='\x00'*16, mode=AES.MODE_ECB, blocksize=16):
    iv, key, message = cbytes(iv), cbytes(key), cbytes(message)
    if message is None:
        return None
    if mode == AES.MODE_ECB:
        cipher = AES.new(key=key, mode=mode)
    else:
        cipher = AES.new(iv=iv, key=key, mode=mode)
    padding = blocksize-len(message)%blocksize
    padding = cbytes(chr(padding)*padding)
    enc = cipher.encrypt(cbytes(message+padding))
    return enc
 
def decrypt_aes(message=None, iv='\x00'*16, key='\x00'*16, mode=AES.MODE_ECB, blocksize=16):
    iv, key, message = cbytes(iv), cbytes(key), cbytes(message)
    if message is None:
        return None
    if mode == AES.MODE_ECB:
        cipher = AES.new(key=key, mode=mode)
    else:
        cipher = AES.new(iv=iv, key=key, mode=mode)
    dec = cipher.decrypt(cbytes(message))
    return dec
 
'''
DES
iv: 8
key: 8
blocksize: 16
'''
def encrypt_des(message=None, iv='\x00'*8, key='\x00'*8, mode=DES.MODE_ECB, blocksize=16):
    iv, key, message = cbytes(iv), cbytes(key), cbytes(message)
    if message is None:
        return None
    if mode == DES.MODE_ECB:
        cipher = DES.new(key=key, mode=mode)
    else:
        cipher = DES.new(iv=iv, key=key, mode=mode)
    padding = blocksize-len(message)%blocksize
    padding = cbytes(chr(padding)*padding)
    enc = cipher.encrypt(cbytes(message+padding))
    return enc
 
def decrypt_des(message=None, iv='\x00'*8, key='\x00'*8, mode=DES.MODE_ECB, blocksize=16):
    iv, key, message = cbytes(iv), cbytes(key), cbytes(message)
    if message is None:
        return None
    if mode == DES.MODE_ECB:
        cipher = DES.new(key=key, mode=mode)
    else:
        cipher = DES.new(iv=iv, key=key, mode=mode)
    dec = cipher.decrypt(cbytes(message))
    return dec
 
'''
Triple DES
iv: 8
key: 24
blocksize: 8
'''
def encrypt_des3(message=None, iv='\x00'*8, key='abcdefghijklmnopqrstuvwx', mode=DES3.MODE_ECB, blocksize=8):
    iv, key, message = cbytes(iv), cbytes(key), cbytes(message)
    if message is None:
        return None
    if mode == DES3.MODE_ECB:
        cipher = DES3.new(key=key, mode=mode)
    else:
        cipher = DES3.new(iv=iv, key=key, mode=mode)
    padding = blocksize-len(message)%blocksize
    padding = cbytes(chr(padding)*padding)
    enc = cipher.encrypt(cbytes(message+padding))
    return enc
 
def decrypt_des3(message=None, iv='\x00'*8, key='abcdefghijklmnopqrstuvwx', mode=DES3.MODE_ECB, blocksize=8):
    iv, key, message = cbytes(iv), cbytes(key), cbytes(message)
    if message is None:
        return None
    if mode == DES3.MODE_ECB:
        cipher = DES3.new(key=key, mode=mode)
    else:
        cipher = DES3.new(iv=iv, key=key, mode=mode)
    dec = cipher.decrypt(cbytes(message))
    return dec
 

 
key0 = 'nameischoiyunsil'.encode()

text_file = "plain.txt"
aes = AES.new(key0, AES.MODE_ECB)
encoded_text = encrypt_aes(text_file)
print("AES encrypt :",encoded_text)

key1 = 'sirichoi'.encode()
des = DES.new(key1, DES.MODE_ECB)
encoded_text = encrypt_des(text_file)
print("DES encrypt :",encoded_text)

key2 = 'hi my name is choiyunsil'.encode()
des3 = DES3.new(key2, DES3.MODE_ECB)
encoded_text = encrypt_des3(text_file)
print("3DES encrypt :",encoded_text)
 
암호화하여 저장한 파일을 생성하고 해당 파일을 복호화 하는 작업을 하겠습니다.
그 결과는 아래와 같습니다.

- 3DES 로 text파일 암호화 복호화
from Crypto.Cipher import DES3
from Crypto.Hash import SHA256 as SHA
from os import path
KSIZE = 1024

class myDES():
    def __init__(self, keytext, ivtext):
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        self.key = key[:24]

        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv  = iv[:8]

    def makeEncInfo(self, filename):
        fillersize = 0
        filesize = path.getsize(filename)
        if filesize%8 != 0:
            fillersize = 8-filesize%8
        filler = '0'*fillersize
        header = '%d'%(fillersize)
        gap = 8-len(header)
        header += '#'*gap

        return header, filler

    def enc(self,filename):
        encfilename = filename + '.enc_3des'
        header, filler = self.makeEncInfo(filename)
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)

        h = open(filename, 'rb')
        hh = open(encfilename, 'wb+')
        enc = header.encode('utf-8')
        content = h.read(KSIZE)
        content = enc + content
        while content:
            if len(content) < KSIZE:
                content += filler.encode('utf-8')
            enc = des3.encrypt(content)
            hh.write(enc)
            content = h.read(KSIZE)
        h.close()
        hh.close()

    def dec(self,encfilename):
        filename = encfilename + '.dec_3des'
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)

        h = open(filename, 'wb+')
        hh = open(encfilename, 'rb')

        content = hh.read(8)
        dec = des3.decrypt(content)
        header = dec.decode()
        fillersize = int(header.split('#')[0])

        content = hh.read(KSIZE)
        while content:
            dec = des3.decrypt(content)
            if len(dec) < KSIZE:
                if fillersize != 0:
                    dec = dec[:-fillersize]
            h.write(dec)
            content = hh.read(KSIZE)
        h.close()
        hh.close()

def main():
    keytext = 'siriyun'
    ivtext = '1234'
    filename = 'plain.txt'
    encfilename = filename + '.enc_3des'

    myCipher = myDES(keytext, ivtext)
    myCipher.enc(filename)
    myCipher.dec(encfilename)

if __name__ == '__main__':
    main()

 

- AES로 text파일 암호화 복호화
AES는 키  크기가 128, 192, 256bit와 블록 암호 크기가 128bit로 구성되어있는 대칭키 암호 알고리즘이다.

from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as SHA

from os import path
KSIZE = 1024

class myAES():
    def __init__(self, keytext, ivtext):
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        self.key = key[:16]

        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv  = iv[:16]

    def makeEncInfo(self, filename):
        fillersize = 0
        filesize = path.getsize(filename)
        if filesize%16 != 0:
            fillersize = 16-filesize%16
        filler = '0'*fillersize
        header = '%d'%(fillersize)
        gap = 16-len(header)
        header += '#'*gap

        return header, filler

        return header, filler

    def enc(self,filename):
        encfilename = filename + '.enc_aes'
        header, filler = self.makeEncInfo(filename)
        ses = AES.new(self.key, AES.MODE_CBC, self.iv)

        h = open(filename, 'rb')
        hh = open(encfilename, 'wb+')
        enc = header.encode('utf-8')
        content = h.read(KSIZE)
        content = enc + content
        while content:
            if len(content) < KSIZE:
                content += filler.encode('utf-8')
            enc = aes.encrypt(content)
            hh.write(enc)
            content = h.read(KSIZE)
        h.close()
        hh.close()

    def dec(self,encfilename):
        filename = encfilename + '.dec_aes'
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)

        h = open(filename, 'wb+')
        hh = open(encfilename, 'rb')

        content = hh.read(8)
        dec = aes.decrypt(content)
        header = dec.decode()
        fillersize = int(header.split('#')[0])

        content = hh.read(KSIZE)
        while content:
            dec = aes.decrypt(content)
            if len(dec) < KSIZE:
                if fillersize != 0:
                    dec = dec[:-fillersize]
            h.write(dec)
            content = hh.read(KSIZE)
        h.close()
        hh.close()

def main():
    keytext = 'nameischoiyunsil'
    ivtext = '1234'
    filename = 'plain.txt'
    encfilename = filename + '.enc'

    myCipher = myAES(keytext, ivtext)
    myCipher.enc(filename)
    myCipher.dec(encfilename)

if __name__ == '__main__':
    main()
 
위와 같이 코드를 작성하면 오류가 발생한다 이는 암호화 메시지 길이가 8바이트의 배수여야 하기 때문이다.
 따라서 plain.txt의 내용을 조금 수정하여 160byte의 문서를 작성하였다. 또한 코드에서 77번째 줄을 filename = 'plain2.txt'으로 고치면 동작함을 알 수 있었다.
최종코드
from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as SHA

from os import path
KSIZE = 1024

class myAES():
    def __init__(self, keytext, ivtext):
        hash = SHA.new()
        hash.update(keytext.encode('utf-8'))
        key = hash.digest()
        self.key = key[:16]

        hash.update(ivtext.encode('utf-8'))
        iv = hash.digest()
        self.iv  = iv[:16]

    def makeEncInfo(self, filename):
        fillersize = 0
        filesize = path.getsize(filename)
        if filesize%16 != 0:
            fillersize = 16-filesize%16
        filler = '0'*fillersize
        header = '%d'%(fillersize)
        gap = 16-len(header)
        header += '#'*gap

        return header, filler

        return header, filler

    def enc(self,filename):
        encfilename = filename + '.enc_aes'
        header, filler = self.makeEncInfo(filename)
        ses = AES.new(self.key, AES.MODE_CBC, self.iv)

        h = open(filename, 'rb')
        hh = open(encfilename, 'wb+')
        enc = header.encode('utf-8')
        content = h.read(KSIZE)
        content = enc + content
        while content:
            if len(content) < KSIZE:
                content += filler.encode('utf-8')
            enc = aes.encrypt(content)
            hh.write(enc)
            content = h.read(KSIZE)
        h.close()
        hh.close()

    def dec(self,encfilename):
        filename = encfilename + '.dec_aes'
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)

        h = open(filename, 'wb+')
        hh = open(encfilename, 'rb')

        content = hh.read(8)
        dec = aes.decrypt(content)
        header = dec.decode()
        fillersize = int(header.split('#')[0])

        content = hh.read(KSIZE)
        while content:
            dec = aes.decrypt(content)
            if len(dec) < KSIZE:
                if fillersize != 0:
                    dec = dec[:-fillersize]
            h.write(dec)
            content = hh.read(KSIZE)
        h.close()
        hh.close()

def main():
    keytext = 'nameischoiyunsil'
    ivtext = '1234'
    filename = 'plain2.txt'
    encfilename = filename + '.enc'

    myCipher = myAES(keytext, ivtext)
    myCipher.enc(filename)
    myCipher.dec(encfilename)

if __name__ == '__main__':
    main()

plain2.txt
hi my name is yun sil Choi.
I am learning about computer science.
Today, i am writing report about computer-security.
I think it is really hard to setting, but the work is so worthwhile. 
nice day

 

   b) 파일을 전송하는 단단한 client-server 프로그램을 작성하고 이를 암호화 하여 전송한후 복호화 하여 확인하라.
-	우선 소켓 프로그래밍을 통해 파일을 전송, 수신하는 기능을 우선 구현하고자 합니다.
 
 
 
 
 
위와 같은 오류가 발생하여 해결 방안을 찾아보았습니다.
 
 
다른 코드를 작성하였지만 이 역시 인터넷 연결이 불가하여 실험 결과는 확인할 수 없었습니다.
 
 

 
윈도우의 명령프롬프트에서 netstat -an 을 입력하면 서버가 생성되서 Listening – 듣고있다는 상태를 체크합니다.
 
연결을 확인하였습니다.
1-a번 문제에서 작성한 DES코드를 불러와 사용하여 암호화된 파일을 전송하고 수신하고자 합니다. 
 

 
암호화 한 파일의 내용을 확인할 수 있었습니다.

   c) 그림판으로 간단한 도형을 그린후 gif 형식으로 저장한후 이를 ECB, CBC 모드로 암호화한후 암호화된 파일을 보여라.
  
결과 파일
 
   
 


2. 문제1에서 테스트 파일을 사용하여 
   a) md5, sha1 등의 hash 방법으로 hash 코드를 구하는 프로그램을 작성하여 hash 코드를 구하라(hash 방법은 2가지 이상의 표준화된 방법을 사용하라.)
-	ModaXterm을 활용한 방안
 
 
암호화를 확인할 수 없는 문제가 발생하였습니다.
 
 
다음과 같은 방법으로 해결하고자 하였습니다.
 
하지만 설치 후에도 해쉬 값을 생성하지 않았습니다.
세션 설정이 되어있지 않은지 확인하였습니다.
 
 
사용방법을 찾아보았으나 교수님께서 실습해 주신 것 처럼 동작하지 않습니다. 저의 설정이 잘못된 것 같습니다.
-	Windows에서 해시값 확인
CLI에서 확인하는 방법
명령 프롬프트 상 - sha256sum.exe 실행
sha256sum.exe 파일 다운로드하여 결과를 확인하였습니다.
이때 문제 1에서 사용하였던 plain2.txt파일을 다운로더 폴더로 옮겨 진행하였습니다.
 
-	우분투에서 해시값 확인
우분투 환경에서 실행결과를 확인하기 위해 VMware를 사용하였습니다.

0.	Vmware를 설치
-	Vmware player download를 검색하여 설치하여줍니다. 너무 최신버전이 아닌 워크스테이션 15를 다운 받았습니다.
 
   
이때 아래와 같은 erro가 발생하여 검색을 하여 해결하였습니다.
 
이 오류는 BIOS설정에서 Virtualization Technology확인을 해 보니 비활성화 되어 있어 발생하였습니다.
  
부팅 과정에서 F2를 눌러 BIOS설정을 확인하여 가상머신 사용을 확인해 주었습니다. Virtualization Technology를 활성화 해 주어 VMware의 실행을 확인할 수 있었습니다.
 
1.	Ubuntu를 설치
Ubuntu download를 검색하여 최신버전의 우분투를 설치해 주었습니다.
 

  
위의 과정을 거쳐 vmware환경에서 우분투 환경을 구축하였습니다. 
 
큰 화면으로 사용하기 위하여 디스플레이 설정을 바꾸어 해상도를 높여주었습니다. 
 
이제 우분투 환경에서 실습을 할 수 있게되었습니다.
a파일을 만든 후, 복사하여 b를 만듭니다. 그 후, 새로운 파일 c를 생성합니다. 그러면 a파일과 b파일은 md5sum값이 동일할 것이고, c 파일만 md5sum값이 다를 것입니다. 실제 예시와 함께 보겠습니다.
 
문제1의 테스트 파일에 대해 md5, sha1 등의 hash 방법으로 hash 코드를 구하여 보겠습니다.
 

-	추가공부
Hash(SHA256)사용하여 암호화, 복호화
from Crypto.Cipher import*  
from Crypto.Hash import SHA256 as SHA  
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
import os  
  
KSIZE = 1024  
  
class myDES():  
    def __init__(self, keytext, ivtext):  
        hash = SHA.new()  
        hash.update(keytext.encode('utf-8'))  
        key = hash.digest()  
        self.key = key[:24]  
  
        hash.update(ivtext.encode('utf-8'))  
        iv = hash.digest()  
        self.iv = iv[:8]  
  
    def makeEncInfo(self, filename):  
        fillersize = 0  
        filesize = os.path.getsize(filename)  
        if filesize % 8 != 0:  
            fillersize = 8 - filesize % 8  
        filler = '0'*fillersize  
        header = '%d'%(fillersize)  
        gap = 8 - len(header)  
        header += '#'*gap  
  
        return header, filler  
  
    def enc(self, filename):  
        encfilename = filename + '.enc'  
        header, filler = self.makeEncInfo(filename)  
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)  
  
        f = open(filename, 'rb')  
        p = open(encfilename, 'wb+')  
  
        enc = header.encode('utf-8')  
        content = f.read(KSIZE)  
        content = enc + content  
  
        while content:  
            if len(content) < KSIZE:  
                content += filler.encode('utf-8')  
            enc = des3.encrypt(content)  
            p.write(enc)  
            content = f.read(KSIZE)  
        f.close()  
        p.close()  
  
    def dec(self, encfilename):  
        filename = encfilename + '.dec'  
        des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)  
  
        f = open(filename, 'wb+')  
        p = open(filename, 'rb')  
  
        content = p.read(8)  
        dec = des3.decrypt(content)  
        header = dec.decode()  
        fillersize = int(header.split('#')[0])  
  
        content = p.read(KSIZE)  
        while content:  
            dec = des3.decrpyt(content)  
            if len(dec) < KSIZE:  
                if fillersize != 0:  
                    dec = dec[:-fillersize]  
            f.write(dec)  
            content = p.reae(KSIZE)  
        f.close()  
        p.close()  
  
if __name__ == "__main__":  
    keytext = 'iloveyou'  
    ivtext = '1234'  
    filename = 'plain.txt'  
    encfilename = filename + '.enc'  
  
    myCipher = myDES(keytext, ivtext)  
    myCipher.enc(filename)  
    myCipher.dec(encfilename)
    
main()
 

모든 크기의 파일에 대해 3DES로 암호화, 복호화 가능한 코드입니다.
-	암호화
        encfilename = filename + '.enc'  
        header, filler = self.makeEncInfo(filename)  
지정된 파일 내용을 1KB씩 읽어서 3DES로 암호화 한 후 새로운 파일에 저장합니다. 암호화 된 내용을 저장할 파일 이름은 원래 파일 이름에 .enc 확장자를 추가하여 만들어집니다. self.makeEncInfo(filename)을 호출하여 헤더와 '0' 문자열을 얻고 각각 변수 header와 filler에 할당합니다.
        enc = header.encode('utf-8')  
        content = f.read(KSIZE)  
        content = enc + content  
파일에서 1KB 씩 읽어서 content에 할당한다. header를 content 앞에 추가한다.
만약 파일 내용이 1KB 미만이면 file.read( )는 남아 있는 크기만큼 모두 읽는다.
        while content:  
            if len(content) < KSIZE:  
                content += filler.encode('utf-8')  
            enc = des3.encrypt(content)  
            p.write(enc)  
            content = f.read(KSIZE)  
content에 내용이 없을 때까지 while 구문을 수행하는 코드입니다. 만약 content의 크기가 KSIZE, 즉 1KB보다 작다면 파일의 끝까지 읽었음을 의미합니다. 따라서 이부분에서 '0' 문자열을 content에 추가합니다.
content를 3DES로 암호화하고 파일에 저장한 후, 파일에 다시 1KB만큼 읽어 content에 할당합니다.
-	복호화
dec(self, encfilename)은 encfilename 으로 지정된 암호화된 파일 내용을 1KB 씩 읽어서 3DES로 복호화 한 후 새로운 파일에 저장합니다.
        content = p.read(8)  
        dec = des3.decrypt(content)  
        header = dec.decode()  
        fillersize = int(header.split('#')[0])  
암호화 파일에서 최초 8byte를 읽어 3DES로 복호화 합니다. 최초 8byte는 헤더이므로 '#'을 구분자로 헤더를 분리한 후 첫번째 멤버를 정수로 변환하면 이 파일의 끝부분에 추가된 문자 '0'의 개수를 얻을 수 있습니다.
        content = p.read(KSIZE)  
        while content:  
            dec = des3.decrpyt(content)  
            if len(dec) < KSIZE:  
                if fillersize != 0:  
                    dec = dec[:-fillersize]  
            f.write(dec)  
            content = p.reae(KSIZE) 
암호화 파일을 먼저 읽고 content에 할당합니다. content에 내용이 없을때 까지 반복 수행합니다.
content를 3DES로 복호화 하고 파일에 저장합니다. 만약 복호화 한 결과가 1KB 보다 작으면 복호화 파일의 마지막 부분이므로 암호화 때 추가한 '0' 문자열을 제거하고 파일에 저장합니다.

[참고자료]
"Python을 사용하여 클라이언트 쪽 암호화," microsoft docs, n.d. 수정, 2021-10-07 접속, https://docs.microsoft.com/ko-kr/azure/storage/common/storage-client-side-encryption-python?tabs=python.
서경룡 교수님 lms강의[3-6주차]
마크 스탬프, 정보보안 이론과 실제(n.p.: IT CookBook, 2015-09-17))
 william stalling 5th, 컴퓨터 보안과 암호 (n.p.: 그린) 
첨부파일 소개
-	Encryption.ipynb : wordkey조합으로 암호화 하는 간단한 실습을 해 보았습니다.
-	1-a.ipynd: 1-a문제의 실습과 마지막 추가 공부에 관한 코드가 있습니다.
-	1-b*.ipynd: 1-b문제와 관련한 실습을 진행한 파일입니다.
-	1-c.ipynd: 1-c문제의 실습 파일 입니다.
다른 파일은 실습 결과 파일과 문제 해결 과정에서 생겨난 파일과 폴더입니다. 실습을 진행한 파일중 레포트에 필요한 결과가 나오지 않은 파일들도 폴더에 존재할 수 있습니다.


