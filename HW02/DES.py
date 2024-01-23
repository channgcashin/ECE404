from BitVector import *
import sys

class DES():
    # class constructor - when creating a DES object , the
    # class’s constructor is called and the instance variables
    # are initialized

    # note that the constructor specifies each instance of DES
    # be created with a key file (str)
    expansion_permutation =[31, 0, 1, 2, 3, 4, 
                            3, 4, 5, 6, 7, 8, 
                            7, 8, 9, 10, 11, 12, 
                            11, 12, 13, 14, 15, 16, 
                            15, 16, 17, 18, 19, 20, 
                            19, 20, 21, 22, 23, 24, 
                            23, 24, 25, 26, 27, 28, 
                            27, 28, 29, 30, 31, 0] 
    
    s_boxes = {i:None for i in range(8)} 

    s_boxes[0] = [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7], 
                    [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8], 
                    [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0], 
                    [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ] 
    
    s_boxes[1] = [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10], 
                    [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5], 
                    [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15], 
                    [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ] 
    
    s_boxes[2] = [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8], 
                    [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1], 
                    [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7], 
                    [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ] 
    
    s_boxes[3] = [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15], 
                    [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9], 
                    [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4], 
                    [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ] 
    
    s_boxes[4] = [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9], 
                    [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6], 
                    [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14], 
                    [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ] 
    
    s_boxes[5] = [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11], 
                    [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8], 
                    [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6], 
                    [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ] 
    
    s_boxes[6] = [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1], 
                    [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6], 
                    [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2], 
                    [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ] 
    
    s_boxes[7] = [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7], 
                    [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2], 
                    [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8], 
                    [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]
    
    key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                        9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                        62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                        13,5,60,52,44,36,28,20,12,4,27,19,11,3]

    key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                        3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                        54,29,39,50,44,32,47,43,48,38,55,33,52,
                        45,41,49,35,28,31]

    shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    p_box = [15, 6, 19, 20, 28, 11, 27, 16, 
                0, 14, 22, 25, 4, 17, 30, 9,
                1, 7, 23, 13, 31, 26, 2, 8,
                18, 12, 29, 5, 21, 10, 3, 24]
    
    def __init__ (self, key):
        # within the constructor , initialize instance variables
        
        # these could be the s-boxes , permutation boxes , and
        # other variables you think each instance of the DES
        # class would need.
        self.key = key
    
    def substitute(self, expanded_half_block):
        output = BitVector(size = 32)
        segments = [expanded_half_block[x*6:x*6+6] for x in range(8)]
        for sindex in range(len(segments)):
            row = 2*segments[sindex][0] + segments[sindex][-1]
            column = int(segments[sindex][1:-1])
            output[sindex*4:sindex*4+4] = BitVector(intVal = self.s_boxes[sindex][row][column], size = 4)
        return output

    def generate_round_keys(self, encryption_key):
        round_keys = []
        key = encryption_key.deep_copy()
        for round_count in range(16):
            [LKey, RKey] = key.divide_into_two()    
            shift = self.shifts_for_round_key_gen[round_count]
            LKey << shift
            RKey << shift
            key = LKey + RKey
            round_key = key.permute(self.key_permutation_2)
            round_keys.append(round_key)
        return round_keys
    

    # encrypt method declaration for students to implement
    # Inputs : message_file (str), outfile (str)
    # Return : void
    def encrypt (self, message_file, out_file):
        # encrypts the contents of the message file and writes
        # the ciphertext to the outfile
        # print("Encrypt function running")
        BLOCKSIZE = 64
        
        with open(message_file, "r") as fpin:
            plaintext_bv = BitVector(textstring = fpin.read())
        ciphertext_bv = BitVector(size = 0)
        with open(self.key, "r") as fpkey:
            key_text = fpkey.read()
        if len(key_text) != 8:
            sys.exit("Key generation needs 8 characters exactly!")
        key_bv = BitVector(textstring = key_text)
        key_bv = key_bv.permute(self.key_permutation_1)
        
        round_keys = self.generate_round_keys(key_bv)
        
        plaintext_bv.pad_from_right(BLOCKSIZE - (len(plaintext_bv) % BLOCKSIZE))
        numblocks = len(plaintext_bv) // BLOCKSIZE
        for i in range(numblocks):
            bv = plaintext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
            [left, right] = bv.divide_into_two()
            # if(i == 0):
            #     print(left.get_bitvector_in_hex())
            #     print(right.get_bitvector_in_hex())

            # Run 16 round of DES
            for round_key in round_keys:
                newright = right.permute(self.expansion_permutation)
                # if(round_key == round_keys[0] and i == 0):
                #     print(newright.get_bitvector_in_hex())  
                newright = newright ^ round_key
                # if(round_key == round_keys[0] and i == 0):
                #     print(newright.get_bitvector_in_hex())
                newright = self.substitute(newright)
                # if(round_key == round_keys[0] and i == 0):
                #     print(newright.get_bitvector_in_hex())
                newright = newright.permute(self.p_box)
                # if(round_key == round_keys[0] and i == 0):
                #     print(newright.get_bitvector_in_hex())
                newright = newright ^ left
                # if(round_key == round_keys[0] and i == 0):
                #     print(newright.get_bitvector_in_hex())
                left = right
                right = newright
                # if(round_key == round_keys[0] and i == 0):
                #     print(left.get_bitvector_in_hex())
                #     print(right.get_bitvector_in_hex())
                # if(i==0):    
                #     print((left + right).get_bitvector_in_hex())
            ciphertext_bv += right + left
            # if(i == 0):
            #     print()
            #     print(ciphertext_bv.get_bitvector_in_hex())
        
        with open(out_file, "w") as fpout:
            fpout.write(ciphertext_bv.get_bitvector_in_hex())

    # decrypt method declaration for students to implement
    # Inputs : encrypted_file (str), outfile (str)
    # Return : void
    def decrypt (self , encrypted_file, out_file):
        # decrypts the contents of the encrypted_file and
        # writes the recovered plaintext to the outfile
        BLOCKSIZE = 64

        with open(encrypted_file, "r") as fpin:
            ciphertext_bv = BitVector(hexstring = fpin.read())
        plaintext_bv = BitVector(size = 0)
        with open(self.key, "r") as fpkey:
            key_text = fpkey.read()
        if len(key_text) != 8:
            sys.exit("Key generation needs 8 characters exactly!")
        key_bv = BitVector(textstring = key_text)
        key_bv = key_bv.permute(self.key_permutation_1)
        
        round_keys = self.generate_round_keys(key_bv)
        
        numblocks = len(ciphertext_bv) // BLOCKSIZE
        for i in range(numblocks):
            bv = ciphertext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
            [right, left] = bv.divide_into_two()

            # Run 16 rounds of DES
            for round_key in reversed(round_keys):
                newleft = left.permute(self.expansion_permutation)
                newleft = newleft ^ round_key
                newleft = self.substitute(newleft)
                newleft = newleft.permute(self.p_box)
                newleft = newleft ^ right

                right = left
                left = newleft

            plaintext_bv += left + right

        with open(out_file, "w") as fpout:
            fpout.write(plaintext_bv.get_text_from_bitvector())
    
    def encrypt_img(self, image_file, out_file):
        # Initialize blocksize
        BLOCKSIZE = 64
        print("Running encryption image")
        
        readfile = BitVector(filename = image_file)
        plaintext_bv = BitVector(size = 0)
        while (readfile.more_to_read):
            plaintext_bv += readfile.read_bits_from_file(BLOCKSIZE)
        
        numReturns = 0
        i = 0    
        while(numReturns < 3):
            if ((plaintext_bv[i*8:(i+1)*8]).get_text_from_bitvector() == "\n"):
                numReturns += 1
            i += 1
        header = plaintext_bv[0:i*8]
        plaintext_bv = plaintext_bv[i*8:]        
        ciphertext_bv = BitVector(size = 0)
        with open(self.key, "r") as fpkey:
            key_text = fpkey.read()
        if len(key_text) != 8:
            sys.exit("Key generation needs 8 characters exactly!")
        key_bv = BitVector(textstring = key_text)
        key_bv = key_bv.permute(self.key_permutation_1)
        
        round_keys = self.generate_round_keys(key_bv)
        
        plaintext_bv.pad_from_right(BLOCKSIZE - (len(plaintext_bv) % BLOCKSIZE))
        numblocks = len(plaintext_bv) // BLOCKSIZE
        for i in range(numblocks):
            bv = plaintext_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
            [left, right] = bv.divide_into_two()

            # Run 16 round of DES
            for round_key in round_keys:
                newright = right.permute(self.expansion_permutation)
                newright = newright ^ round_key
                newright = self.substitute(newright)
                newright = newright.permute(self.p_box)
                newright = newright ^ left

                left = right
                right = newright

            ciphertext_bv += right + left
        
        # Save ciphertext to output file
        with open(out_file, "w", encoding="utf-8") as fpout:
            fpout.write(header.get_text_from_bitvector())
            fpout.write(ciphertext_bv.get_text_from_bitvector())    

# drive the encryption / decryption process
if __name__ == "__main__":
    # example of construction of DES object instance
    cipher = DES(key = sys.argv[3])
    if(sys.argv[1] == '-e'):
        cipher.encrypt(sys.argv[2], sys.argv[4])
    elif(sys.argv[1] == '-d'):
        cipher.decrypt(sys.argv[2], sys.argv[4])
    elif(sys.argv[1] == '-i'):
        cipher.encrypt_img(sys.argv[2], sys.argv[4])
    else:
        print("Error With Arguments! Try again.")