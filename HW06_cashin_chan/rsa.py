import sys
from PrimeGenerator import *
from BitVector import *

class RSA():
    def __init__(self , e) -> None:
        self.e = e
        self.n = None
        self.d = None
        self.p = None
        self.q = None
    
    def generate(self, p_txt, q_txt):
        generator = PrimeGenerator(bits = 128)
        p = 0
        q = 0
        setBit = BitVector(bitstring = '11')

        while True:
            p = generator.findPrime()
            q = generator.findPrime()
            p_bv = BitVector(intVal = p)
            q_bv = BitVector(intVal = q)

            if p_bv[0:2] == setBit and q_bv[0:2] == setBit and p != q and p % self.e != 1 and q % self.e != 1:
                break
            else:
                continue

        # write to file
        p_out = open(p_txt, "w")
        q_out = open(q_txt, "w")

        p_out.write(str(p))
        q_out.write(str(q))

        p_out.close()
        q_out.close()


    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        ciphertext_bv = BitVector(size=0)
        plaintext_bv = BitVector(filename = plaintext)

        self.n = self.p * self.q

        while (plaintext_bv.more_to_read):
            bitvec = plaintext_bv.read_bits_from_file(128)

            if bitvec._getsize() > 0:
                if bitvec._getsize() < 128:
                    bitvec.pad_from_right(128 - bitvec._getsize())
                
                bitvec.pad_from_left(128)

                ciphertext_bv += BitVector(intVal=pow(bitvec.int_val(), self.e, self.n), size=256)

        with open(ciphertext, "w") as fpout:
            fpout.write(ciphertext_bv.get_bitvector_in_hex())
        
    def decrypt(self , ciphertext:str , recovered_plaintext:str) -> None:
        p_bv = BitVector(intVal = self.p)
        q_bv = BitVector(intVal = self.q)

        self.n = self.p * self.q
        totient = (self.p-1) * (self.q-1)
        totient_bv = BitVector(intVal = totient)
        e_bv = BitVector(intVal = self.e)
        d_bv = BitVector(size = 0)
        d_bv = e_bv.multiplicative_inverse(totient_bv)

        self.d = int(d_bv)

        q_mi = q_bv.multiplicative_inverse(p_bv)
        p_mi = p_bv.multiplicative_inverse(q_bv)

        plaintext_bv = BitVector(size=0)
        ciphertext_file = open(ciphertext)
        ciphertext_bv = BitVector(hexstring = ciphertext_file.read())

        for i in range(0, ciphertext_bv._getsize()//256):
            bitvec = ciphertext_bv[i*256:(i+1)*256]

            vp = pow(bitvec.int_val(), self.d, self.p)
            vq = pow(bitvec.int_val(), self.d, self.q)
            xp = self.q * (int(q_mi) % self.p)
            xq = self.p * (int(p_mi) % self.q)

            plaintext_bv += BitVector(intVal=(vp * xp + vq * xq) % self.n, size=256)[128:]

        with open(recovered_plaintext, "w") as fpout:
            fpout.write(plaintext_bv.get_bitvector_in_ascii())

if __name__ == "__main__":
    cipher = RSA(e=65537)
    
    if sys.argv[1] == "-g":
        cipher.generate(p_txt=sys.argv[2], q_txt=sys.argv[3])
    elif sys.argv[1] == "-e":
        p_file = open(sys.argv[3])
        q_file = open(sys.argv[4])
        p = p_file.read()
        q = q_file.read()
        cipher.p = int(p)
        cipher.q = int(q)
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
    elif sys.argv[1] == "-d":
        p_file = open(sys.argv[3])
        q_file = open(sys.argv[4])
        p = p_file.read()
        q = q_file.read()
        cipher.p = int(p)
        cipher.q = int(q)
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])