import sys
from BitVector import *
import copy

class AES():
    AES_modulus = BitVector(bitstring='100011011')
    subBytesTable = []
    invSubBytesTable = []

    def __init__ (self, keyfile, toggle):
        self.keyfile = keyfile # keyfile of HW04
        self.toggle = toggle

    #Create two 256-element arrays for byte substitution, one for encryption and one for decryption
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


    #g() function taken from lecture 8 code
    def gee(self, keyword, round_constant, byte_sub_table):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    #generate key expansion Function taken from lecture 8 code
    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
        #  60 keywords in the key schedule for 256
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
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

    #Function taken from lecture 8
    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable

    def subBytes(self, stateArray):
        #SubBytes
        if(self.toggle != 'd'):
            for i in range(4):
                for j in range(4):
                    index = stateArray[j][i]
                    index = ord(index.get_bitvector_in_ascii())
                    stateArray[j][i] = BitVector(textstring = chr(self.subBytesTable[index]))
        

        #InvSubBytes
        elif(self.toggle == 'd'):
            for i in range(4):
                for j in range(4):
                    index = stateArray[j][i]
                    index = ord(index.get_bitvector_in_ascii())
                    stateArray[j][i] = BitVector(textstring = chr(self.invSubBytesTable[index]))
        return stateArray

    def shift(self, array,numShift):
        numShift %= len(array) #num shift % length
        shiftedArray = array[numShift:] + array[:numShift]
        return shiftedArray


    def shiftRow(self, stateArray):
        #ShiftRow
        if(self.toggle != 'e'):
            for i in range(1,4):
                #print(i)
                stateArray[i] = self.shift(stateArray[i],i)

        #InvShiftRow
        elif(self.toggle == 'd'):
            for i in range(1,4):
                stateArray[i] = self.shift(stateArray[i],-i)
        return stateArray

    def mixCol(self, stateArray):
        #MixCol
        if(self.toggle != 'd'):
            tmp = copy.deepcopy(stateArray) #copy to a temp
            hold1 = BitVector(intVal = 2) #create holders
            hold2 = BitVector(intVal = 3)
            
            #first row
            for i in range(4):
                stateArray[0][i] =  (hold1.gf_multiply_modular(tmp[0][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[1][i], self.AES_modulus,8)) ^ (tmp[2][i]) ^ (tmp[3][i])
            #second row
                stateArray[1][i] =  (hold1.gf_multiply_modular(tmp[1][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[2][i], self.AES_modulus,8)) ^ (tmp[3][i]) ^ (tmp[0][i])
            #third row
                stateArray[2][i] =  (hold1.gf_multiply_modular(tmp[2][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[3][i], self.AES_modulus,8)) ^ (tmp[0][i]) ^ (tmp[1][i])
            #fourth row
                stateArray[3][i] =  (hold1.gf_multiply_modular(tmp[3][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[0][i], self.AES_modulus,8)) ^ (tmp[1][i]) ^ (tmp[2][i])
            
        #InvMixCol
        elif(self.toggle == 'd'):
            tmp = copy.deepcopy(stateArray) #copy to a temp 
            hold1 = BitVector(hexstring = "0E")
            hold2 = BitVector(hexstring = "0B")
            hold3 = BitVector(hexstring = "0D")
            hold4 = BitVector(hexstring = "09")
            
            #first row
            for i in range(4):
                stateArray[0][i] =  (hold1.gf_multiply_modular(tmp[0][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[1][i], self.AES_modulus,8)) ^ (hold3.gf_multiply_modular(tmp[2][i], self.AES_modulus,8)) ^ (hold4.gf_multiply_modular(tmp[3][i], self.AES_modulus,8))
            #second row
                stateArray[1][i] =  (hold1.gf_multiply_modular(tmp[1][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[2][i], self.AES_modulus,8)) ^ (hold3.gf_multiply_modular(tmp[3][i], self.AES_modulus,8)) ^ (hold4.gf_multiply_modular(tmp[0][i], self.AES_modulus,8))
            #third row
                stateArray[2][i] =  (hold1.gf_multiply_modular(tmp[2][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[3][i], self.AES_modulus,8)) ^ (hold3.gf_multiply_modular(tmp[0][i], self.AES_modulus,8)) ^ (hold4.gf_multiply_modular(tmp[1][i], self.AES_modulus,8))
            #fourth row
                stateArray[3][i] =  (hold1.gf_multiply_modular(tmp[3][i], self.AES_modulus,8)) ^ (hold2.gf_multiply_modular(tmp[0][i], self.AES_modulus,8)) ^ (hold3.gf_multiply_modular(tmp[1][i], self.AES_modulus,8)) ^ (hold4.gf_multiply_modular(tmp[2][i], self.AES_modulus,8))

        return stateArray 

    #bv to stateArray
    def bvToState(self, bv):
        stateArray = [[0 for x in range(4)] for x in range(4)] #create state array
        for i in range(4):
                for j in range(4):
                    stateArray[j][i] = bv[32 * i + 8 * j:32 * i + 8 * (j + 1)] #set each index to a bv
        return stateArray

    #state to bv
    def stateToBv(self, stateArray):
        bv = BitVector(size = 0)
        for i in range(4):
                for j in range(4):
                    bv += self.stateArray[j][i]
        return bv


    #do key expansion and return list of round keys
    def keyExpansion(self, keyBv):
    #create the key expansion array
        keyWords = self.gen_key_schedule_256(keyBv)
        keySchedule = []

        for index,word in enumerate(keyWords):
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i * 8:i * 8  + 8].intValue())
            keySchedule.append(keyword_in_ints)

        #create the round keys
        num_rounds = 14 
        round_keys = [None for i in range(num_rounds + 1)] 
        for i in range(num_rounds + 1):
            round_keys[i] = (keyWords[i * 4] + keyWords[i * 4 + 1] + keyWords[i * 4 + 2] + keyWords[i * 4 + 3])
        return round_keys

    def encrypt_img(self, bv, key_bv):
        round_keys = self.keyExpansion(key_bv)

        bv = bv ^ BitVector(bitstring = round_keys[0])
        #convert pt block to input state array
        stateArray = self.bvToState(bv)

        #14 rounds of encryption
        for i in range(14):
            #step 1 
            stateArray = self.subBytes(stateArray)
            #step 2
            stateArray = self.shiftRow(stateArray)
            #step 3
            if(i<13):
                stateArray = self.mixCol(stateArray)
            #step 4
            bv = BitVector(size = 0)
            for k in range(4):
                for j in range(4):
                    bv += stateArray[j][k]
            bv ^= round_keys[i + 1]
            stateArray = self.bvToState(bv)

        return bv

    def ctr_aes_image(self, iv, image_file, enc_image):
        BLOCKSIZE = 128
        outFile = open(enc_image, 'wb')

        # generate sub tables
        self.genTables()
        
        with open(self.keyfile, "r") as fpkey:
            key_text = fpkey.read()
        if len(key_text) != 32:
            sys.exit("Key generation needs 32 characters exactly!")
        key_bv = BitVector(textstring = key_text)

        ivInt = iv.int_val()

        bv = BitVector(filename = image_file)
        
        numReturns = 0
        while(numReturns < 3):
            img_bv = bv.read_bits_from_file(8)
            if img_bv.get_bitvector_in_ascii()=='\n':
                numReturns += 1
            img_bv.write_to_file(outFile)

        while (bv.more_to_read):
            img_bv = bv.read_bits_from_file(BLOCKSIZE)
            if len(img_bv) < BLOCKSIZE:
                temp = BitVector(intVal = 0, size = BLOCKSIZE-len(img_bv))
                img_bv = img_bv + temp

            enc_block = self.encrypt_img(iv, key_bv)

            ciphertext_bv = img_bv ^ enc_block
            
            #Write ciphertext block to file
            ciphertext_bv.write_to_file(outFile)
            
            #Increment IV
            ivInt += 1
            iv = BitVector(intVal=ivInt, size = BLOCKSIZE)

    def encrypt_x931(self, bv, key_bv):
        BLOCKSIZE = 128

        round_keys = self.keyExpansion(key_bv)

        bv = bv ^ BitVector(bitstring = round_keys[0])
        #convert pt block to input state array
        stateArray = self.bvToState(bv)

        #14 rounds of encryption
        for i in range(14):
            #step 1 
            stateArray = self.subBytes(stateArray)
            #step 2
            stateArray = self.shiftRow(stateArray)
            #step 3
            if(i<13):
                stateArray = self.mixCol(stateArray)
            #step 4
            bv = BitVector(size = 0)
            for k in range(4):
                for j in range(4):
                    bv += stateArray[j][k]
            bv ^= round_keys[i + 1]
            stateArray = self.bvToState(bv)

        return bv
    
    def x931(self, v0, dt, totalNum, outfile):
        self.genTables()

        with open(self.keyfile, "r") as fpkey:
            key_text = fpkey.read()
        if len(key_text) != 32:
            sys.exit("Key generation needs 32 characters exactly!")
        key_bv = BitVector(textstring = key_text)  

        randNums = []

        for i in range(totalNum):
            dt_enc = self.encrypt_x931(dt, key_bv)
            rand = dt_enc ^ v0
            rand = self.encrypt_x931(rand, key_bv)
            randNums.append(rand)

            v0 = rand ^ dt_enc
            v0 = self.encrypt_x931(v0, key_bv)

        with open(outfile, "w") as fpout:
            for nums in randNums:
                fpout.write(str(nums.int_val()) + '\n')

if __name__ == "__main__":
    cipher = AES(toggle=sys.argv[2], keyfile=sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], ciphertext = sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext = sys.argv[2], decrypted = sys.argv[4])
    elif sys.argv[1] == "-i":
        cipher.ctr_aes_image(iv=BitVector(textstring="counter-mode-ctr"), image_file = sys.argv[2], enc_image = sys.argv[4])
    elif sys.argv[1] == "-r":
        cipher.x931(v0=BitVector(textstring="counter-mode-ctr"), dt=BitVector(intVal=501, size=128), totalNum=int(sys.argv[2]), outfile=sys.argv[4])
    else:
        sys.exit("Incorrect Command - Line Syntax")