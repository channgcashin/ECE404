import sys
from BitVector import *

###
## Decrypt message given an encrypted file and a bitvector key
###

def cryptBreak(ciphertextFile, key_bv):
    
    # Initialize variables for decryption
    PassPhrase = "Hopes and dreams of a million years"
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8 
    
    # Reduce the passphrase to a bit array of size BLOCKSIZE
    bv_iv = BitVector(bitlist = [0] * BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i * numbytes : (i + 1) * numbytes]
        bv_iv ^= BitVector(textstring = textstr)
        
    # Create a bitvector from the ciphertext hex string
    fpin = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring = fpin.read())
        
    # Create a bitvector for storing the decrypted plaintext bit array
    msg_decrypted_bv = BitVector(size = 0)  
    
    # Carry out differential XORing of bit blocks and decryption
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        msg_decrypted_bv += bv
    
    #return string of bit vector
    return msg_decrypted_bv.get_text_from_bitvector()