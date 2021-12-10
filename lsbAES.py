#Import necessary modules
import cv2
import numpy as np

from base64 import b64decode,b64encode
import numpy as np
import matplotlib.pyplot as plt

import pywt
import pywt.data

import numpy as np


# method to convert text to unicode matrix
def text2Unicode(text):
  text_matrix = np.zeros((16),dtype=int)  # 16 element vector with zeros

  for i in range(16):
    text_matrix[i] = ord(text[i])     # ord converts char to unicode integer value

  text_matrix = np.reshape(text_matrix,(4,4)) # reshape the vector to a 4x4 matrix
  return text_matrix


# funtion to convert unicode matrix to text
def unicode2Text(matrix):
  text = ""
  matrix = matrix.flatten()
  for i in range(16):
    text+=chr(int(matrix[i])) # chr converts unicode integer to unicode character
  return text


# method to substitute bytes using rjindael s-box
def subBytes(A):
  s_box = np.load('Lookup Tables/s_box.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row, sub_col = A[row,col]//16, A[row,col]%16
      B[row,col] = s_box[sub_row,sub_col]
  return B


# method to restore bytes of using inverse rjindael s-box
def invSubBytes(A):
  inv_s_box = np.load('Lookup Tables/inv_s_box.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row, sub_col = A[row,col]//16, A[row,col]%16
      B[row,col] = inv_s_box[sub_row,sub_col]
  return B


# method to shift rows
def shiftRows(A):
  B = np.zeros((4,4),dtype=int)
  # keep 1st row intact
  B[0,:] = A[0,:]
  # shift each element of 2nd row 1 step to the left 
  B[1,0],B[1,1],B[1,2],B[1,3] = A[1,1],A[1,2],A[1,3],A[1,0] 
  # shift each element of 3rd row 2 steps to the left
  B[2,0],B[2,1],B[2,2],B[2,3] = A[2,2],A[2,3],A[2,0],A[2,1]
  # shift each element of 4th row 3 steps to the left
  B[3,0],B[3,1],B[3,2],B[3,3] = A[3,3],A[3,0],A[3,1],A[3,2]
  return B


# method to restore shifted rows
def invShiftRows(A):
  B = np.zeros((4,4),dtype=int)
  # keep 1st row intact
  B[0,:] = A[0,:]
  # shift each element of 2nd row 1 step to the left 
  B[1,1],B[1,2],B[1,3],B[1,0] = A[1,0],A[1,1],A[1,2],A[1,3] 
  # shift each element of 3rd row 2 steps to the left
  B[2,2],B[2,3],B[2,0],B[2,1] = A[2,0],A[2,1],A[2,2],A[2,3]
  # shift each element of 4th row 3 steps to the left
  B[3,3],B[3,0],B[3,1],B[3,2] = A[3,0],A[3,1],A[3,2],A[3,3]
  return B


#method to mix columns using Galois Field E Table
def mixCol(A):
  e_table = np.load('Lookup Tables/E_Table.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row , sub_col = A[row,col]//16,A[row,col]%16
      B[row,col] = e_table[sub_row,sub_col]
  return B


#method to restore mixed columns using Galois Field L Table
def invMixCol(A):
  l_table = np.load('Lookup Tables/L_Table.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row , sub_col = A[row,col]//16,A[row,col]%16
      B[row,col] = l_table[sub_row,sub_col]
  return B


#method to add round key to text
def addRoundKey(A,key):
    B = np.zeros((4,4),dtype=int)
    B = np.bitwise_xor(A,key)
    return B


#method to restore text after adding round key
def removeRoundKey(A,key):
    B = np.zeros((4,4),dtype=int)
    B = np.bitwise_xor(A,key)
    return B


# Main AES Encrtption Method
def aesEncrypt(plain_text,key):
    key = text2Unicode(key)
    length = len(plain_text)
    cipher_text = "" 
    
    # splitting  plain_text into substrings of length 16 each and adding whitspaces to shorter substrings    
    plain_text_split = []
    for i in range(length//16):
        plain_text_split.append(plain_text[0+16*i:16+16*i])
    if not length%16==0:        
        plain_text_split.append(plain_text[16*(length//16):])
    if len(plain_text_split[-1])<16:
        while(len(plain_text_split[-1])<16):
            plain_text_split[-1]+=' '
    
    # encrypting each sub string
    for sub_string in plain_text_split : 
        A0 = text2Unicode(sub_string)
        A1 = subBytes(A0)
        A2 = shiftRows(A1)
        A3 = mixCol(A2)
        A4 = addRoundKey(A3,key)
        cipher_text+=unicode2Text(A4)
    return cipher_text


# Main AES Decryption Method
def aesDecrypt(cipher_text,key):
    key = text2Unicode(key)
    decrypted_text = ""
    length = len(cipher_text)
    # splitting  cipher text into substrings of length 16 each    
    cipher_text_split = []
    for i in range(length//16):
        cipher_text_split.append(cipher_text[0+16*i:16+16*i])
    
    # decrypting each substring
    for sub_string in cipher_text_split:
        cipher_text = text2Unicode(sub_string)
        A3 = removeRoundKey(cipher_text,key)
        A2 = invMixCol(A3)
        A1 = invShiftRows(A2)
        A0 = invSubBytes(A1)
        decrypted_text+=unicode2Text(A0)
    return decrypted_text


#Define the class
class Project():
    
    def __init__(self, im):
        self.image = im
        self.height, self.width, self.nbchannels = im.shape
        self.size = self.width*self.height

        #Mask used to set bits:1->00000001, 2->00000010 ... (using OR gate)
        self.maskONEValues = [1<<i for i in range(8)]
        self.maskONE = self.maskONEValues.pop(0) #remove first value as it is being used

        #Mask used to clear bits: 254->11111110, 253->11111101 ... (using AND gate)
        self.maskZEROValues = [255-(1<<i) for i in range(8)]
        self.maskZERO = self.maskZEROValues.pop(0)
        
        self.curwidth = 0  # Current width position
        self.curheight = 0 # Current height position
        self.curchan = 0   # Current channel position

    '''
    Function to insert bits into the image -- the actual steganography process
    param: bits - the binary values to be inserted in sequence
    '''
    def put_binary_value(self, bits):
        
        for c in bits:  #Iterate over all bits
            val = list(self.image[self.curheight,self.curwidth]) #Get the pixel value as a list (val is now a 3D array)
            if int(c):  #if bit is set, mark it in image
                val[self.curchan] = int(val[self.curchan])|self.maskONE 
            else:   #Else if bit is not set, reset it in image
                val[self.curchan] = int(val[self.curchan])&self.maskZERO 

            #Update image
            self.image[self.curheight,self.curwidth] = tuple(val)

            #Move pointer to the next space
            self.next_slot() 

    '''
    Function to move the pointer to the next location, and error handling if msg is too large
    '''
    def next_slot(self):
        if self.curchan == self.nbchannels-1: #If looped over all channels
            self.curchan = 0
            if self.curwidth == self.width-1: #Or the first channel of the next pixel of the same line
                self.curwidth = 0
                if self.curheight == self.height-1:#Or the first channel of the first pixel of the next line
                    self.curheight = 0
                    if self.maskONE == 128: #final mask, indicating all bits used up
                        raise SteganographyException("No available slot remaining (image filled)")
                    else: #else go to next bitmask
                        self.maskONE = self.maskONEValues.pop(0)
                        self.maskZERO = self.maskZEROValues.pop(0)
                else:
                    self.curheight +=1
            else:
                self.curwidth +=1
        else:
            self.curchan +=1

    '''
    Function to read in a bit from the image, at a certain [height,width][channel]
    '''
    def read_bit(self): #Read a single bit int the image
        val = self.image[self.curheight,self.curwidth][self.curchan]
        val = int(val) & self.maskONE
        #move pointer to next location after reading in bit
        self.next_slot()

        #Check if corresp bitmask and val have same set bit
        if val > 0:
            return "1"
        else:
            return "0"
    
    def read_byte(self):
        return self.read_bits(8)

    '''
    Function to read nb number of bits
    Returns image binary data and checks if current bit was masked with 1
    '''
    def read_bits(self, nb): 
        bits = ""
        for i in range(nb):
            bits += self.read_bit()
        return bits

    #Function to generate the byte value of an int and return it
    def byteValue(self, val):
        return self.binary_value(val, 8)

    #Function that returns the binary value of an int as a byte
    def binary_value(self, val, bitsize):
        #Extract binary equivalent
        binval = bin(val)[2:]
        #Check if out-of-bounds
        if len(binval)>bitsize:
            raise SteganographyException("Binary value larger than the expected size, catastrophic failure.")

        #Making it 8-bit by prefixing with zeroes
        while len(binval) < bitsize:
            binval = "0"+binval
            
        return binval
    '''
    Functions to Encode and Decode text into the images
    '''
    def encode_text(self, txt):
        l = len(txt)
        print("LENGTH:",l)
        binl = self.binary_value(l, 16) #Generates 4 byte binary value of the length of the secret msg
        self.put_binary_value(binl) #Put text length coded on 4 bytes
        for char in txt: #And put all the chars
            c = ord(char)
            self.put_binary_value(self.byteValue(c))
        return self.image
       
    def decode_text(self):
        ls = self.read_bits(16) #Read the text size in bytes
        l = int(ls,2)   #Returns decimal value ls
        i = 0
        unhideTxt = ""
        while i < l: #Read all bytes of the text
            tmp = self.read_byte() #So one byte
            i += 1
            unhideTxt += chr(int(tmp,2)) #Every chars concatenated to str
        return unhideTxt

ch=0
Message="Secure_Data_Encryption_using_AES_and_Hybrid_Steganography\n"
print('\n'.join('{:^80}'.format(s) for s in Message.split('\n')))

print("\n")
while ch!=3:

    Message = "Which operation would you like to perform?\n1.Encode Text\n2.Decode Text\n3.Exit Program\n"

    #Print to console in center-display format
    print('\n'.join('{:^60}'.format(s) for s in Message.split('\n')))

    ch=int(input())
    if ch==3:
        break
    
    if ch==1:
        original = pywt.data.camera()

        # Wavelet transform of image, and plot approximation and details
        titles = ['Approximation', ' Horizontal detail',
                'Vertical detail', 'Diagonal detail']
        coeffs2 = pywt.dwt2(original, 'bior1.3')
        LL, (LH, HL, HH) = coeffs2
        fig = plt.figure(figsize=(12, 3))
        for i, a in enumerate([LL]):
            ax = fig.add_subplot(1, 4, i + 1)
            ax.imshow(a, interpolation="nearest", cmap=plt.cm.gray)
            ax.set_title(titles[i], fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])

        fig.tight_layout()
        plt.savefig('D:\project work\kaa.png',bbox_inches='tight')
        plt.show()

        wd='D:\project work\kaa.png'

        #Create object of class
        obj=Project(cv2.imread(wd))

        print("\nMessage to be encoded into source image: ")
        plain_text = input("Enter a string to be encoded : ")
        cipher_key = input("Enter a 16 character long key for encryption : ")    
        print("Encrypting : ")    
        encrypted_msg = aesEncrypt(plain_text,cipher_key)
        print("The encrpyted text is : {}".format(encrypted_msg))

        #Invoke encode_text() function
        print("\nCreating encrypted image.")
        encrypted_img=obj.encode_text(encrypted_msg)
        
        print("\nEnter destination image filename: ")
        dest=input()

        #Write into destination
        print("\nSaving image in destination.")
        cv2.imwrite(dest,encrypted_img)

        print("Encryption complete.")
        print("The encrypted file is available at",dest,"\n")

        '''To display the original image and the new image'''
##        image1 = cv2.imread(wd)
##        image2 = cv2.imread(dest)
##        cv2.imshow('image1',image1);
##        cv2.imshow('image2',image2);
##        cv2.waitKey(0)
##        cv2.destroyAllWindows()
        
    
    elif ch==2:
        wd=dest
        img=cv2.imread(wd)
        obj=Project(img)
        encrypted_msg = obj.decode_text()
        print("\nEncrypted message obtained from decrypting image is:\n",encrypted_msg)
        print("Decrypting : ")
        decrypted_text = aesDecrypt(encrypted_msg,cipher_key)
        print("The decrpyted text is : {}".format(decrypted_text))

print("Thank you.")
