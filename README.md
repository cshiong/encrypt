# Encrypt
This program provides a way to protect your data(files) with high security by encrypting with multiple layer of securities.

# Usage

To encrypt or decrypt files and director

To run this program. you need provide either of the two commands: e or d
 and one required argument -i which is the full name of the file you like to encrypt or decrypt.
 there is one optional argument -o if it is provided, it will be the result file name, if not, the result file will be overwrite the original input file.

1. sample command:\n
 ./encrypt e -i inputFile -o outputFile
 it will encrypt the inputFile and the encrypted file will be stored in the outputFile
 
 ./encrypt d -i inputFile
 it will decrypt inputFile and the result will overwrite itself.
 
 it will ask you password to fulfill the command, the password is the only thing you need to remember when you encrypt or decrypt file.
 if you forget it, there is no way to redeem it.

 *Note: for directory we will encrypt the folder and archived into .zip file, if the output file name not provided .zip suffix, it will be added.

# Technology

## PBKDF2 (Password-Based Key Derivation Function 2)  
Using PBKDF2 function to generate the encrypt key from the password.

## CBC(cipher block chaining) encryption
Cipher block chaining (CBC) is a mode of operation for a block cipher (one in which a sequence of bits are encrypted as a single unit or block with a cipher key applied to the entire block).

## SHA256-HMAC (Keyed-Hash Message Authentication Code)
Used to simultaneously verify both the data integrity and the authentication of a message. 

