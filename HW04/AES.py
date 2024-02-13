import sys
from BitVector import *

class AES ():
    AES_modulus = BitVector(bitstring='100011011')
    subBytesTable = [] # SBox for encryption
    invSubBytesTable = [] # SBox for decryption
    
    # table for mixCols operation
    mixColsTable = [[BitVector(hexstring = "02"), BitVector(hexstring = "03"), BitVector(hexstring = "01"), BitVector(hexstring = "01")],
                    [BitVector(hexstring = "01"), BitVector(hexstring = "02"), BitVector(hexstring = "03"), BitVector(hexstring = "01")],
                    [BitVector(hexstring = "01"), BitVector(hexstring = "01"), BitVector(hexstring = "02"), BitVector(hexstring = "03")],
                    [BitVector(hexstring = "03"), BitVector(hexstring = "01"), BitVector(hexstring = "01"), BitVector(hexstring = "02")]]
    # table for invMixCols operation
    invMixColsTable = [[BitVector(hexstring = "0E"), BitVector(hexstring = "0B"), BitVector(hexstring = "0D"), BitVector(hexstring = "09")],
                       [BitVector(hexstring = "09"), BitVector(hexstring = "0E"), BitVector(hexstring = "0B"), BitVector(hexstring = "0D")],
                       [BitVector(hexstring = "0D"), BitVector(hexstring = "09"), BitVector(hexstring = "0E"), BitVector(hexstring = "0B")],
                       [BitVector(hexstring = "0B"), BitVector(hexstring = "0D"), BitVector(hexstring = "09"), BitVector(hexstring = "0E")]]

    # class constructor - when creating an AES object , the class ’s constructor is executed and instance variables are initialized
    def __init__ (self, toggle, keyfile):
        self.keyfile = keyfile # keyfile of HW04
        self.toggle = toggle # argument for toggling encryption or decryption

    # From lecture 8
    def genTables(self):
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
        # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))

            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))
        
 
    # This is the g() function you see in Figure 4 of Lecture 8.
    def gee(self, keyword, round_constant, byte_sub_table):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
            newword[:8] ^= round_constant
            round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    # From lecture 8
    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.subBytesTable
        # We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        # 256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        # block with. Subsequently, each of the 14 rounds uses 4 keywords from the key
        # schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8]
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

    def subBytes(self, stateArray):
        # SubBytes
        if(self.toggle == '-e'):
            for i in range(4):
                for j in range(4):
                    index = stateArray[j][i]
                    index = ord(index.get_bitvector_in_ascii())
                    stateArray[j][i] = BitVector(textstring = chr(self.subBytesTable[index]))

        # InvSubBytes
        elif(self.toggle == '-d'):
            for i in range(4):
                for j in range(4):
                    index = stateArray[j][i]
                    index = ord(index.get_bitvector_in_ascii())
                    stateArray[j][i] = BitVector(textstring = chr(self.invSubBytesTable[index]))
        return stateArray
    
    def shiftRows(self, stateArray):
        # ShiftRows
        if(self.toggle == '-e'):
            return [[stateArray[0][0], stateArray[0][1], stateArray[0][2], stateArray[0][3]],
                    [stateArray[1][1], stateArray[1][2], stateArray[1][3], stateArray[1][0]],
                    [stateArray[2][2], stateArray[2][3], stateArray[2][0], stateArray[2][1]],
                    [stateArray[3][3], stateArray[3][0], stateArray[3][1], stateArray[3][2]]]

        # InvShiftRows
        elif(self.toggle == '-d'):
            return [[stateArray[0][0], stateArray[0][1], stateArray[0][2], stateArray[0][3]],
                    [stateArray[1][3], stateArray[1][0], stateArray[1][1], stateArray[1][2]],
                    [stateArray[2][2], stateArray[2][3], stateArray[2][0], stateArray[2][1]],
                    [stateArray[3][1], stateArray[3][2], stateArray[3][3], stateArray[3][0]]]
        
    def mixCols(self, stateArray):
        temp = [[BitVector(size = 8) for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    # MixCols
                    if(self.toggle == '-e'):
                        temp[i][j] ^= self.mixColsTable[i][k].gf_multiply_modular(stateArray[k][j], self.AES_modulus, 8)
                    # InvMixCols
                    elif(self.toggle == '-d'):
                        temp[i][j] ^= self.invMixColsTable[i][k].gf_multiply_modular(stateArray[k][j], self.AES_modulus, 8)
        stateArray = temp
        return stateArray
    
    # From lecture 8
    def keyExpansion(self, key_bv):
        # generate key expansion array
        keyWords = self.gen_key_schedule_256(key_bv)
        keySchedule = []

        for index, word in enumerate(keyWords):
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            keySchedule.append(keyword_in_ints)

        # generate round keys
        num_rounds = 14 
        round_keys = [None for i in range(num_rounds + 1)] 
        for i in range(num_rounds + 1):
            round_keys[i] = (keyWords[i * 4] + keyWords[i * 4 + 1] + keyWords[i * 4 + 2] + keyWords[i * 4 + 3])
        return round_keys

    def createStateArray(self, bv):
        stateArray = [[0 for x in range(4)] for x in range(4)] #create state array
        for i in range(4):
            for j in range(4):
                stateArray[j][i] = bv[32 * i + 8 * j: 32 * i + 8 * (j + 1)] 
        return stateArray
    
    def breakDownStateArray(self, stateArray):
        bv = BitVector(size = 0)
        for i in range(4):
                for j in range(4):
                    bv += stateArray[j][i]
        return bv

    # encrypt - method performs AES encryption on the plaintext and writes the ciphertext to disk
    # Inputs : plaintext (str) - filename containing plaintext
    # ciphertext (str) - filename containing ciphertext
    # Return : void
    def encrypt (self, plaintext, ciphertext):
        BLOCKSIZE = 128
        
        # generate sub tables
        self.genTables()

        with open(plaintext, "r") as fpin:
            plaintext_bv = BitVector(textstring = fpin.read())
        ciphertext_bv = BitVector(size = 0)
        with open(self.keyfile, "r") as fpkey:
            key_text = fpkey.read()
        if len(key_text) != 32:
            sys.exit("Key generation needs 32 characters exactly!")
        key_bv = BitVector(textstring = key_text)

        round_keys = self.keyExpansion(key_bv)
        
        plaintext_bv.pad_from_right(BLOCKSIZE - (len(plaintext_bv) % BLOCKSIZE))
        numblocks = len(plaintext_bv) // BLOCKSIZE
        for i in range(numblocks):
            # XOR round key
            bv = plaintext_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
            bv ^= round_keys[0]
            # Convert to state array
            stateArray = self.createStateArray(bv)

            # Start round process
            for j in range(14):
                # SubBytes
                stateArray = self.subBytes(stateArray)
                # ShiftRows
                stateArray = self.shiftRows(stateArray)
                # MixCols
                if j < 13:
                    stateArray = self.mixCols(stateArray)
                # AddRoundKey
                bv = self.breakDownStateArray(stateArray)
                bv ^= round_keys[j+1]
                stateArray = self.createStateArray(bv)
                #if(i == 0 and j == 0):
                #    print(self.breakDownStateArray(stateArray).get_bitvector_in_hex())
            ciphertext_bv += self.breakDownStateArray(stateArray)

        with open(ciphertext, "w") as fpout:
            fpout.write(ciphertext_bv.get_bitvector_in_hex())

    # decrypt - method performs AES decryption on the ciphertext and writes the recovered plaintext to disk
    # Inputs : ciphertext (str) - filename containing ciphertext
    # decrypted (str) - filename containing recovered plaintext
    # Return : void
    def decrypt (self , ciphertext, decrypted):
        BLOCKSIZE = 128
        
        # generate sub tables
        self.genTables()

        with open(ciphertext, "r") as fpin:
            ciphertext_bv = BitVector(hexstring = fpin.read())
        plaintext_bv = BitVector(size = 0)
        with open(self.keyfile, "r") as fpkey:
            key_text = fpkey.read()
        if len(key_text) != 32:
            sys.exit("Key generation needs 32 characters exactly!")
        key_bv = BitVector(textstring = key_text)

        round_keys = self.keyExpansion(key_bv)

        numblocks = len(ciphertext_bv) // BLOCKSIZE
        for i in range(numblocks):
            # XOR last round key
            bv = ciphertext_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
            bv ^= round_keys[-1]
            # Convert to state array
            stateArray = self.createStateArray(bv)

            # Start round process
            for j in range(14):
                # InvShiftRows
                stateArray = self.shiftRows(stateArray)
                # InvSubBytes
                stateArray = self.subBytes(stateArray)
                # InvAddRoundKey
                bv = self.breakDownStateArray(stateArray)
                bv ^= round_keys[13-j]
                stateArray = self.createStateArray(bv)
                # InvMixCols
                if j < 13:
                    stateArray = self.mixCols(stateArray)
            plaintext_bv += bv

        with open(decrypted, "w") as fpout:
            fpout.write(plaintext_bv.get_text_from_bitvector())


if __name__ == "__main__":
    cipher = AES(toggle = sys.argv[1], keyfile = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], ciphertext = sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext = sys.argv[2], decrypted = sys.argv[4])
    else :
        sys.exit("Incorrect Command - Line Syntax") 