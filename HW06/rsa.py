import sys

class RSA():
    def __init__(self , e) -> None:
        self.e = e
        self.n = None
        self.d = None
        self.p = None
        self.q = None

    # You are free to have other RSA class methods you deem necessary for your solution

    def encrypt(self , plaintext:str , ciphertext:str) -> None:
    # your implemenation goes here
        
    def decrypt(self , ciphertext:str , recovered_plaintext:str) -> None:
    # your implemenation goes here

if __name__ == "__main__":
    cipher = RSA(e=65537)
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])