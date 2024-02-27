import sys
from PrimeGenerator import *
from BitVector import *
import solve_pRoot

class breakRSA():
    def __init__(self, e) -> None:
        self.e = e
        self.n1 = None
        self.n2 = None
        self.n3 = None
        self.d = None
        self.p1 = None
        self.p2= None
        self.p3 = None
        self.q1 = None
        self.q2 = None
        self.q3 = None

    # gcd function
    def gcd(self, a, b):
        if a == 0: return b
        if b == 0: return a
        if a == b: return a

        if a > b:
            return self.gcd(a-b, b)
        return self.gcd(a, b-a)
    
    def generate(self):
        generator = PrimeGenerator(bits = 128)
        p = 0
        q = 0
        setBit = BitVector(bitstring = '11')

        while True:
            p = generator.findPrime()
            q = generator.findPrime()
            p_bv = BitVector(intVal = p)
            q_bv = BitVector(intVal = q)

            if p_bv[0:2] == setBit and q_bv[0:2] == setBit and p != q and (p-1) % self.e == 1 or (q-1) % self.e == 1:
                break
            else:
                continue

        return p, q
        
    def encrypt(self, plaintext:str, n, ciphertext:str) -> None:
        ciphertext_bv = BitVector(size=0)
        plaintext_bv = BitVector(filename = plaintext)

        while (plaintext_bv.more_to_read):
            bitvec = plaintext_bv.read_bits_from_file(128)

            if bitvec._getsize() > 0:
                if bitvec._getsize() < 128:
                    bitvec.pad_from_right(128 - bitvec._getsize())
                
                bitvec.pad_from_left(128)

                ciphertext_bv += BitVector(intVal=pow(bitvec.int_val(), self.e, n), size=256)

        with open(ciphertext, "w") as fpout:
            fpout.write(ciphertext_bv.get_bitvector_in_hex())

    def break_encrypt(self, plaintext:str, ciphertext1:str, ciphertext2:str, ciphertext3:str, nfile:str) -> None:
        self.p1, self.q1 = self.generate()
        self.n1 = self.p1 * self.q1
        self.p2, self.q2 = self.generate()
        self.n2 = self.p2 * self.q2
        self.p3, self.q3 = self.generate()
        self.n3 = self.p3 * self.q3

        self.encrypt(plaintext, self.n1, ciphertext1)
        self.encrypt(plaintext, self.n2, ciphertext2)
        self.encrypt(plaintext, self.n3, ciphertext3)

        with open(nfile, "w") as fpout:
            fpout.write(str(self.n1))
            fpout.write("\n")
            fpout.write(str(self.n2))
            fpout.write("\n")
            fpout.write(str(self.n3))
            fpout.write("\n")
    
    def break_crack(self , enc1_txt:str, enc2_txt:str, enc3_txt:str, nfile:str, cracked_txt:str) -> None:
        fpin = open(nfile)
        n1 = fpin.readline()
        n2 = fpin.readline()
        n3 = fpin.readline()

        self.n1 = int(n1)
        self.n2 = int(n2)
        self.n3 = int(n3)
        n1_bv = BitVector(intVal = self.n1)
        n2_bv = BitVector(intVal = self.n2)
        n3_bv = BitVector(intVal = self.n3)

        N = self.n1 * self.n2 * self.n3

        N1 = self.n2 * self.n3
        N2 = self.n1 * self.n3
        N3 = self.n1 * self.n2

        N1_bv = BitVector(intVal = N1)
        N1_mi = N1_bv.multiplicative_inverse(n1_bv)
        c1 = N1 * int(N1_mi)
        N2_bv = BitVector(intVal = N2)
        N2_mi = N2_bv.multiplicative_inverse(n2_bv)
        c2 = N2 * int(N2_mi)
        N3_bv = BitVector(intVal = N3)
        N3_mi = N3_bv.multiplicative_inverse(n3_bv)
        c3 = N3 * int(N3_mi)

        enc1_file = open(enc1_txt)
        enc2_file = open(enc2_txt)
        enc3_file = open(enc3_txt)

        bv1 = BitVector(hexstring=enc1_file.read())
        bv2 = BitVector(hexstring=enc2_file.read())
        bv3 = BitVector(hexstring=enc3_file.read())

        plaintext_bv = BitVector(size=0)

        for i in range(0, bv1._getsize()//256):
            bitvec1 = bv1[i*256:(i+1)*256]
            bitvec2 = bv2[i*256:(i+1)*256]
            bitvec3 = bv3[i*256:(i+1)*256]

            a = (c1 * int(bitvec1) + c2 * int(bitvec2) + c3 * int(bitvec3)) % N
            m = solve_pRoot.solve_pRoot(3, a)

            plaintext_bv += BitVector(intVal=m, size=256)[128:]

        with open(cracked_txt, "w") as fpout:
            fpout.write(plaintext_bv.get_bitvector_in_ascii())

if __name__ == "__main__":
    cipher = breakRSA(e=3)
    
    if sys.argv[1] == "-e":
        cipher.break_encrypt(plaintext=sys.argv[2], ciphertext1=sys.argv[3], ciphertext2=sys.argv[4], ciphertext3=sys.argv[5], nfile=sys.argv[6])
    elif sys.argv[1] == "-c":
        cipher.break_crack(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])