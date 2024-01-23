from cryptBreak import cryptBreak
from BitVector import *

if len(sys.argv) != 3:
    sys.exit("Wrong arguments!")
infile = sys.argv[1]

for val in range(0, 9999):
    key = BitVector(intVal = val, size = 16)
    decryptedMessage = cryptBreak(infile , key)
    if "Ferrari" in decryptedMessage:
        # Extract plaintext from the decrypted bitvector:    
        outputtext = decryptedMessage;    
        print('Encryption Broken!')
        # Write plaintext to the output file:
        FILEOUT = open(sys.argv[2], 'w')
        FILEOUT.write('Decrypted Message: \n')                                           
        FILEOUT.write(outputtext + '\n\n')
        FILEOUT.write('Key Integer Value: \n')
        FILEOUT.write(str(val))                                                   
        FILEOUT.close() 
        break
    else:
        print('Not Encrypted Yet')