# Build a symmetric block cipher with the following requirements:
# Must be a Feistel structure with 16 rounds
# Input plaintext = 32-bit block
# Output ciphertext = 32-bit block
# Key = 32 bits, producing subkey of 16 bits for each round
# The function F must implements operations defined on GF(2^16)
# Implements CBC mode for plaintext longer than 32 bits

#By Bagus Alwan 22/492140/PA/21072 and Kreshnayogi Dava Berliansyach 22/496686/PA/21352


#EXTRA FUNCTIONS

def add_padding(text, block_size):   #added padding to make sure the CBC function works
    temp = (len(text) % block_size)
    if(temp == 0):
       padding_length = temp
    else:
      padding_length = block_size - (len(text) % block_size)
    padded_text = text + '0' * padding_length
    return padded_text

def binary_converter(string):
    result = ''

    for char in string:
        binary_char = bin(ord(char))[2:].zfill(8)  #convert character to ASCII code, then to binary
        result += binary_char

    return result

def string_converter(string):
    blocks = [string[i:i+8] for i in range(0, len(string), 8)] #split the binary string into 8-bit blocks

    letters = [chr(int(chunk, 2)) for chunk in blocks] #convert each block back to ASCII character

    return ''.join(letters)

def remove_padding(text):
    temp = text[-8:]

    while(temp == '00000000'):
      text = text[:-8]
      temp = text[-8:]

    return format(text)


#ENCRYPTION FUNCTIONS

def AdditionGF16(text, key):  #XOR
    result = text ^ key
    return (result)

def SubKeyGen(key, round): #Complex Subkey Generator
    Rkey = (key << round | key >> (32 - round)) & 0xFFFFFFFF #Permutating the key by shifting it based on the round number
    left = Rkey >> 16
    right = Rkey & 0xFFFF

    subkey = AdditionGF16(left, right) #XOR the right and left side to get the round key

    return (subkey)

def Feistel(text, key, round = 0):
  if(round<16):

    subkey = SubKeyGen(key, round)

    left = text >> 16
    right = text & 0xFFFF
    F = AdditionGF16(right, subkey) #F Function

    Nright = AdditionGF16(left, F)
    Nleft = right

    newtext = (Nleft << 16) | Nright

    return Feistel(newtext, key, round + 1)

  else:
    left = text >> 16
    right = text & 0xFFFF
    final = (right << 16) | left # Last Swap for Output 17
    return (final)
  
def CBC(text, key): #CBC Funcion
  round = int(len(text) / len(key))
  n = 0
  keys = int(key, 2)
  c = keys
  count = 1
  encrypted_blocks = []
  while(round>0):
    temp = int(text[n:n+len(key)], 2)
    res = AdditionGF16(c, temp)
    result = Feistel(res, keys)
    c = result
    round -= 1
    n += len(key)
    count += 1
    encrypted_blocks.append(format(result, '032b'))


  encrypted_text = ''.join(encrypted_blocks)
  return encrypted_text


#DECRYPTION FUNCTIONS

def ReverseFeistel(text, key, round = 0):
    if(round<16):

      subkey = SubKeyGen(key, 15 - round)

      left = text >> 16
      right = text & 0xFFFF
      F = AdditionGF16(right, subkey) #F Function

      Nright = AdditionGF16(left, F)
      Nleft = right

      newtext = (Nleft << 16) | Nright

      return ReverseFeistel(newtext, key, round + 1)

    else:
      left = text >> 16
      right = text & 0xFFFF
      final = (right << 16) | left # Last Swap for Output 17
      return (final)

def CBC_decrypt(text, key): #decryption of CBC function
    round = int(len(text) / len(key))
    key_int = int(key, 2)
    block_size = len(key)
    decrypted_text = ''
    prev_block = key_int  # Initialize previous block with key for CBC decryption
    n = 0
    while (round>0):
        block = int(text[n:n + block_size], 2)
        decrypted_block = ReverseFeistel(block, key_int)
        plain_block = decrypted_block ^ prev_block
        prev_block = block  # Update previous block for next iteration
        decrypted_text += format(plain_block, '032b')
        n += block_size
        round -= 1
    return decrypted_text


#CODE RUNNER

plain_text = 'Hello'
key  = '11100101101011100101101000001111'

print('PlainText          : ', plain_text)

text = binary_converter(plain_text)
print('BinaryText         : ', text)

#Add padding as necessary
text = add_padding(text, len(key))
print('PaddedText         : ', text)


#encryption
if(len(text)>32):
  CipherText = CBC(text, key)
else:
  text = int(text, 2)
  key = int(key, 2)
  CipherText = format(Feistel(text, key),'032b')


print("CipherBinary       : ", CipherText)

CipherText = string_converter(CipherText)
print("CipherText         : ", CipherText)

CipherText = binary_converter(CipherText) #turn back the string back to binary for decryption


if(len(CipherText)>32):
  DecryptedText = CBC_decrypt(CipherText, key)
  print('DecryptedText      : ', DecryptedText)
else:
  CipherText = int(CipherText, 2)
  DecryptedText = format(ReverseFeistel(CipherText, key), '032b')
  print('DecryptedText      : ', DecryptedText)

stringbin = remove_padding(DecryptedText) #remove padding as necessary

string = string_converter(stringbin)
print('Decrypted Message  : ',string)