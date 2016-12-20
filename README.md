# encrypt
This program provide high security to encrypt/decrypt your data(files).

# Usage

To encrypt or decrypt files.

To run this program. you need provide either of the two commands: e or d
 and one required argument -i which is the full name of the file you like to encrypt or decrypt.
 there is one optional argument -o if it is provided, it will be the result file name, if not, the result file will be overwrite the original input file.

1. sample command:
 ./encrypt e -i inputFile -o outputFile
 it will encrypt the inputFile and the encrypted file will be stored in the outputFile
 
 ./encrypt d -i inputFile
 it will decrypt inputFile and the result will overwrite itself.
 
 it will ask you password to fulfill the command, the password is the only think you need to remember when you encrypt or decrypt file.
 if you forget it, there is no way to redeem it.

 

# Technology