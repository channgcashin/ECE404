import sys
import os
import copy
import BitVector
from BitVector import *

class AES():
    AES_modulus = BitVector(bitstring='100011011')
    subBytesTable = []
    invSubBytesTable = []

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


    #substitute bytes function
    def subBytes(self, stateArray,EorD):
        #Encrypt mode
        if(EorD == 'e'):
            for i in range(4):
                for j in range(4):
                    index = stateArray[j][i]
                    index = ord(index.get_bitvector_in_ascii())
                    stateArray[j][i] = BitVector(textstring = chr(self.subBytesTable[index]))
        

        #decrypt mode
        elif(EorD == 'd'):
            for i in range(4):
                for j in range(4):
                    index = stateArray[j][i]
                    index = ord(index.get_bitvector_in_ascii())
                    stateArray[j][i] = BitVector(textstring = chr(self.invSubBytesTable[index])) # uses inverse table for decryption
        return stateArray

    #Helper function to shift array
    def shift(self, array,numShift):
        numShift %= len(array) #num shift % length
        shiftedArray = array[numShift:] + array[:numShift]
        return shiftedArray


    def shiftRow(self, stateArray,EorD):
        #ShiftRows
        if(EorD == 'e'):
            for i in range(1,4):
                #print(i)
                stateArray[i] = self.shift(stateArray[i],i)

        #InvShiftRows
        elif(EorD == 'd'):
            for i in range(1,4):
                stateArray[i] = self.shift(stateArray[i],-i)
        return stateArray

    def mixCol(self, stateArray,EorD):
        #MixColumns encrypt
        if(EorD == 'e'):
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
            
        #InvMixColumns
        elif(EorD == 'd'):
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




    def encrypt(self, plaintext, keyfile, ciphertext):
        #open key
        keyFile = open(keyfile,'r')
        keyText = keyFile.read()
        
        #close key file
        keyFile.close()

        #create s boxs
        self.genTables()

        #key calcs
        key = keyText.strip()
        key += '0' * (256 // 8 - len(key)) if len(key) < 256 // 8 else key[:256 // 8]  
        key_bv = BitVector( textstring = key )
        round_keys = self.keyExpansion(key_bv)
    

        bv = BitVector(filename = plaintext)

        #open cipher file
        ciphertext = open(ciphertext,'w')

        while(bv.more_to_read):
            bvRead = bv.read_bits_from_file(128)
            if(bvRead.length() != 128):
                #pad with zeros
                bvRead.pad_from_right(128 - bvRead.length())
            # xor the bv first four words of the key schedule
            bvRead = bvRead ^ BitVector(bitstring = round_keys[0])

            #convert pt block to input state array
            stateArray = self.bvToState(bvRead)

            #14 rounds of encryption
            for i in range(14):
                #step 1 
                stateArray = self.subBytes(stateArray,'e')
                #step 2
                stateArray = self.shiftRow(stateArray,'e')
                #step 3
                if(i<13):
                    stateArray = self.mixCol(stateArray,'e')
                #step 4
                bvRead = BitVector(size = 0)
                for k in range(4):
                    for j in range(4):
                        bvRead += stateArray[j][k]
                bvRead ^= round_keys[i + 1]
                stateArray = self.bvToState(bvRead)
                
        
            ciphertext.write(bvRead.get_bitvector_in_hex())

        bv.close_file_object()
        ciphertext.close()

    def decrypt(self, ciphertext, keyfile, plaintext):
        #open key 
        keyFile = open(keyfile,'r')
        keyText = keyFile.read()

        #close key file
        keyFile.close()

        #key calcs
        key = keyText.strip()
        key += '0' * (256 // 8 - len(key)) if len(key) < 256 // 8 else key[:256 // 8]  
        key_bv = BitVector( textstring = key )
        round_keys = self.keyExpansion(key_bv)

        #open cyphertext file
        ciphertext = open(ciphertext.strip(),'r')
        data = ciphertext.read()
        ciphertext.close()

        #create s-box
        self.genTables()

        bv = BitVector(hexstring = data)
        g = 0
        h = 128

        #open pt file
        plaintext = open(plaintext,'wb') 

        while(h <= bv.length()):
            #bvRead = BitVector(size = 0)
            bvRead = bv[g:h]
            g += 128
            h += 128

            #pad
            if(bvRead.length() != 128):
                bvRead.pad_from_right(128 - bvRead.length())

            #xor the bv before creating the stateArray with the last four words of the key schedule
            bvRead = bvRead ^ BitVector(bitstring = round_keys[14])
            # test for step 0 - it works
            
            #convert pt block to input state array
            stateArray = self.bvToState(bvRead)

            #14 rounds decryption
            for i in range(14):
                #step 1
                stateArray = self.shiftRow(stateArray,'d')
                #step 2
                stateArray = self.subBytes(stateArray,'d')
                #step 3
                bvTest = BitVector(size = 0)
                for k in range(4):
                    for j in range(4):
                        bvTest += stateArray[j][k]
                bvTest ^= round_keys[13 - i]
                stateArray = self.bvToState(bvTest)
                #step 4
                if(i<13):
                    stateArray = self.mixCol(stateArray,'d')
                #step 5

            bvReadDc = self.stateToBv(stateArray)
            bvReadDc.write_to_file(plaintext)
        plaintext.close()

if __name__ == "__main__":
    cipher = AES()

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], keyfile= sys.argv[3], ciphertext = sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext = sys.argv[2], keyfile= sys.argv[3], decrypted = sys.argv[4])
    else:
        sys.exit("Incorrect Command - Line Syntax")