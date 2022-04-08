# XOR-XBOX-Mapping Embedding Code

import os
import timeit
import cv2
import csv
import argparse
import binascii
import numpy as np
from AES_func import sbox, _sbox, rcGen, gfGen

def RotWord(word):    
    return word[1:] + word[0:1]

def ShiftRows(state):
    Nb = len(state)
    n = [word[:] for word in state]

    for i in range(Nb):
        for j in range(4):
            n[i][j] = state[(i+j) % Nb][j]
    return n
    
def InvShiftRows(state):
    Nb = len(state)
    n = [word[:] for word in state]

    for i in range(Nb):
        for j in range(4):
            n[i][j] = state[(i-j) % Nb][j]
    return n
    
def MixColumns(state):
    Nb = len(state)
    n = [word[:] for word in state]
    
    for i in range(Nb):
        s0 = state[i][0]
        s1 = state[i][1]
        s2 = state[i][2]
        s3 = state[i][3]
        n[i][0] = (gfGen(2,s0) ^ gfGen(3,s1) ^ s2 ^ s3)
        n[i][1] = (s0 ^ gfGen(2,s1) ^ gfGen(3,s2) ^ s3)
        n[i][2] = (s0 ^ s1 ^ gfGen(2,s2) ^ gfGen(3,s3))
        n[i][3] = (gfGen(3,s0) ^ s1 ^ s2 ^ gfGen(2,s3))
    return n

def InvMixColumns(state):
    Nb = len(state)
    n = [word[:] for word in state]

    for i in range(Nb):
        s0 = state[i][0]
        s1 = state[i][1]
        s2 = state[i][2]
        s3 = state[i][3]
        n[i][0] = (gfGen(14,s0) ^ gfGen(11,s1) ^ gfGen(13,s2) ^ gfGen(9,s3))
        n[i][1] = (gfGen(9,s0) ^ gfGen(14,s1) ^ gfGen(11,s2) ^ gfGen(13,s3))
        n[i][2] = (gfGen(13,s0) ^ gfGen(9,s1) ^ gfGen(14,s2) ^ gfGen(11,s3))
        n[i][3] = (gfGen(11,s0) ^ gfGen(13,s1) ^ gfGen(9,s2) ^ gfGen(14,s3))
    return n
    
def Str2Hex(message):    
    if len(message) < 16:        
        nKey = range(16 - len(message))
        temp = message
        for i in nKey:
            temp = '0' + temp
        message = temp
    else: 
        None   
    
    key = binascii.hexlify(str.encode(message)).decode()    
    return key
    
def Float2Int(values):
    # Convert from float to int
    return round(float(values))
    
def Convert2D_To_3D(table):
    # Convert from string values to int
    ax = 0
    for x in table:
        ay = 0
        for y in x:
            table[ax][ay] = round(float(table[ax][ay]))
            ay+=1
        ax+=1
    return np.reshape(table, [-1,2,2])
     
def SubWord(word): 
    return [sbox[byte] for byte in word]

def SubBytes(state):
    return [[sbox[byte] for byte in word] for word in state]
    
def InvSubBytes(state):
    return [[_sbox[byte] for byte in word] for word in state]
    
def AddRoundKey(state, key):    
    Nb = len(state)
    new_state = [[None for j in range(4)] for i in range(Nb)]
    
    for i, word in enumerate(state):       
        for j, byte in enumerate(word):          
            if type(byte) != int:
                byte = int(byte)
            if type(key[i][j]) != int:
                key[i][j] = int(key[i][j])
            
            new_state[i][j] = byte ^ key[i][j]

    return new_state
    
def Process_Key(key, Nk=4):        
    key = key.replace(" ", "")        
    return [[int(key[i*8+j*2:i*8+j*2+2], 16) for j in range(4)]
                for i in range(Nk)]
            
def Inv_Process_Key(key, Nk=4):           
    hex_code = ''
    for j in key:   
        for i in j:            
            hex_code = hex_code + format(i, '02x')
    return hex_code
                            
def Cipher(block, w, Nb=4, Nk=4, Nr=10):
    state = AddRoundKey(block, w[:Nb])   

    for r in range(1, Nr):     
        state = SubBytes(state)        
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, w[r*Nb:(r+1)*Nb])        
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, w[Nr*Nb:(Nr+1)*Nb])

    return state
        
def InvCipher(block, w, Nb=4, Nk=4, Nr=10):
    state = AddRoundKey(block, w[Nr*Nb:(Nr+1)*Nb])

    for r in range(Nr-1, 0, -1):
        state = InvShiftRows(state)
        state = InvSubBytes(state)
        state = AddRoundKey(state, w[r*Nb:(r+1)*Nb])
        state = InvMixColumns(state)

    state = InvShiftRows(state)
    state = InvSubBytes(state)
    state = AddRoundKey(state, w[:Nb])

    return state
    
def Inv_XBOX(table, n=16):
    out = []
    for i in range(n):
        out.append(int(table[i*2:i*2+2],16))
    return out
    
def XBOX_Generate(mode):
    # Generate X-Boxes Table
    #XOR Table 
    #00 = {0,5,10,15}
    #01 = {1,4,11,14}
    #10 = {2,7,8,13}
    #11 = {3,6,9,12}

    # Box_Mapping = 
    #1RC00:[0,0,0];1RC01:[0,1,0];1RC10:[0,0,1];1RC11:[0,1,1]
    #2RC00:[1,0,0];2RC01:[1,1,0];2RC10:[1,0,1];2RC11:[1,1,1]
    #3RC00:[2,0,0];3RC01:[2,1,0];3RC10:[2,0,1];3RC11:[2,1,1]
    #4RC00:[3,0,0];4RC01:[4,1,0];4RC10:[3,0,1];4RC11:[3,1,1]
    XOR_List = np.array([[0,5,10,15],[1,4,11,14],[2,7,8,13],[3,6,9,12]])
    for s in XOR_List:
        s = np.random.shuffle(s)    
        
    flat_s = np.stack(XOR_List, axis=-1).flatten()
    if mode == 1:        
        return flat_s
    else: 
        return np.reshape(flat_s, (-1,2,2))

def KeyExpansion(key, Nb=4, Nk=4, Nr=10):
    w = []
    for word in key:                  
        w.append(word[:])

    i = Nk

    while i < Nb * (Nr + 1):        
        temp = w[i-1][:]
        if i % Nk == 0:            
            temp = SubWord(RotWord(temp))
            temp[0] ^= rcGen(i//Nk)
        elif Nk > 6 and i % Nk == 4:
            temp = SubWord(temp)

        for j in range(len(temp)):
            temp[j] ^= w[i-Nk][j]

        w.append(temp[:])
        i += 1

    return w
    
def Main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--function", required=True, 
               help="Function Available: 0: Encrypt, 1: Decrypt, 2: Embed Evaluation, 3: Extract Evaluation")
    ap.add_argument("-m", "--mode", required=True,
               help="Mode Available: S: Steganophaphy Only, SE: Cryptography + Steganophaphy")
    #Evaluation Arguments (Optional)
    ap.add_argument("-i", "--iteration", required=False, 
               help="iteration = loop number")
    args = ap.parse_args()

    # args = vars(ap.parse_args())

    if args.function != None:
        #Encrypt Mode        
        if args.function == '0':            
            cvr_path = input("cover image input:")
            sec_path = input("secret image input:")
            output_path = input("enter output path for stego image:")
            if args.mode == 'S':
                Steg_Embed(cvr_path, sec_path, output_path, 'S')
            else:
                message_key = input("enter password:")
                hex_key = Process_Key(Str2Hex(message_key))               
                # Generate xbox table as cipher key
                xbox_flat = XBOX_Generate(1)                
                xbox_table = np.reshape(xbox_flat, (-1,2,2))
                
                temp = ''   
                for i in xbox_flat:           
                    temp = temp + binascii.hexlify(i).decode()[:2]        
                
                _cp_key = SubBytes(Process_Key(temp))
                cp_key = KeyExpansion(_cp_key,4,4,10)
                encrypt_table = Cipher(hex_key,cp_key,4,4,10)                
                cipher_xbox_table = np.reshape(encrypt_table, (-1,2,2))                
                Steg_Embed(cvr_path, sec_path, output_path, 'SE', xbox_table, _cp_key, cipher_xbox_table)
        #Decrypt Mode
        elif args.function == '1':
            stg_path = input("stego image input:")
            key_path = input("enter key path:")
            output_path = input("enter output path for secret image:")
            if args.mode == 'S':               
                Steg_Extract(stg_path, key_path, output_path, 'S')                
            else:
                message_key = input("enter password:")
                pass_key = Process_Key(Str2Hex(message_key))               
                
                # Generate xbox table as cipher key
                with open(key_path + '_xKeyTable.csv', newline='') as csvfile:
                    dc_table = list(csv.reader(csvfile,delimiter=','))                
                    dc_table = np.reshape(dc_table, (-1,4))                    
                                      
                with open(key_path + '_xKeySE.csv', newline='') as csvfile:
                    _dc_key = list(csv.reader(csvfile,delimiter=','))                   
                    for j, pre_key in enumerate(_dc_key):
                        for i, nest_key in enumerate(pre_key):
                            _dc_key[i][j] = int(_dc_key[i][j])
                    dc_key = KeyExpansion(_dc_key,4,4,10)
                    
                decrypt_table = InvCipher(dc_table,dc_key,4,4,10)              
                if decrypt_table == pass_key:
                    decipher_xbox_table = np.reshape(decrypt_table, (-1,2,2))                
                    decipher_xbox_table = Inv_XBOX(Inv_Process_Key(InvSubBytes(_dc_key)))
                    decipher_xbox_table = np.reshape(decipher_xbox_table, (-1,2,2))
                    
                    Steg_Extract(stg_path, key_path, output_path, 'SE', decipher_xbox_table)
                else:
                    print('Incorrect Password!, Decryption Failed!')
                    exit(0)
        elif args.function >= '2':
            Evaluation_Prg(args.iteration,args.function,args.mode)
        else:
            None
    else:
        exit(0)

def Steg_Embed(cover, message, output, mode, xbox_table=None, key=None, cp_xbox_table=None): 
    #Read the image
    cvr_img = cv2.imread(cover,0) #0 = GRAYSCALE, 1 = COLOR     
    cvr_img = cv2.resize(cvr_img, (256,256))

    # msg_img = cv2.imread(args["message_image"],0)
    msg_img = cv2.imread(message,0)
    msg_img = cv2.resize(msg_img, (128,128))

    if mode == 'S':
        xbox_table = XBOX_Generate(0)
    else:
        None
        
    # Flatten Image
    cvr_flatten = cvr_img.flatten()
    msg_flatten = msg_img.flatten()
    out = []
        
    # Split x into 4 part (2-Bit each), Map with XOR_XBOX
    m_out = []
    k_out = []

    counter = 0
    for m in msg_flatten:
        m = np.binary_repr(m, width=8)        
        b = np.array([0,0,0,0])    
        loop = range(4) 
        counter = 0
        for y in loop:            
            count_multiply = counter*2                       
            bx = m[count_multiply]
            by = m[count_multiply+1]    
            if bx == '0' and by == '0':
                b[counter] = xbox_table[counter,0,0]
            elif bx == '0' and by == '1':
                b[counter] = xbox_table[counter,1,0]
            elif bx == '1' and by == '0':
                b[counter] = xbox_table[counter,0,1]       
            else:
                b[counter] = xbox_table[counter,1,1]              
            m_out.append(b[counter])  
            counter += 1
            
    counter = 0
    for c in cvr_flatten:        
        c = np.binary_repr(c, width=8)
        
        XOR_a = c[-4:]
        XOR_b = np.binary_repr(m_out[counter], width=4)  
            
        XOR_rst = int(XOR_a,2) ^ int(XOR_b,2)
        XOR_key = int(XOR_a,2)
        
        k_out.append(XOR_key)
                    
        bt_a = c[:4]   
        bt_b = str(bin(XOR_rst)[2:].zfill(len(bt_a)))
        bt_rep = int((bt_a + bt_b),2)
        
        out.append(bt_rep)
        counter += 1

    stg_img = np.reshape(np.array(out), (256,256))    

    # Convert back to 2D Array for output.csv
    if mode == 'S':
        xbox_table2D = np.reshape(xbox_table, (-1,2))         
    else:
        xbox_table2D = np.reshape(cp_xbox_table, (-1,2))       
        np.savetxt(output + '_xKeySE.csv', key, delimiter=",", fmt='%s')
        
    cv2.imwrite('stego.png', stg_img)    
    np.savetxt(output + '_xKey.csv', k_out, delimiter=",",fmt='%s')
    np.savetxt(output + '_xKeyTable.csv', xbox_table2D, delimiter=",", fmt='%s')
    
    print("Encrypted!")
    return ''
    
def Steg_Extract(image, key, output, mode, xbox_table=None):
    # read the stego image
    stg_img = cv2.imread(image,0)
    stg_img = cv2.resize(stg_img, (256,256))

    # flatten the pixel into binary
    stg_flatten = stg_img.flatten()
    out = []
    
    # Key Reference for BitXOR
    with open(key + '_xKey.csv', newline='') as csvfile:
            xbox_key = list(csv.reader(csvfile,delimiter=','))
    
    if mode == 'S':
        with open(key + '_xKeyTable.csv', newline='') as csvfile:
            xbox_table2D = list(csv.reader(csvfile,delimiter=','))
            xbox_table = Convert2D_To_3D(xbox_table2D)        
    else: 
        None
        
    # Initialize Variable
    d = '' # Delimiter
    counter = 0
    key_count = 0
    n = []
    for m in stg_flatten:    
        m = np.binary_repr(m, width=8)
        # retrieve the last 4 bits and refer to xbox_table and reverse the process
        x = False # Boolean to check values found
              
        XOR_a = m[-4:]      
        XOR_b = np.binary_repr(Float2Int(xbox_key[key_count][0]), width=4)
        bt_rcv = int(XOR_a,2) ^ int(XOR_b,2)

        key_count += 1
        for a in xbox_table:       
            ax = 0 
            for b in a:                               
                bx = 0
                for c in b:                   
                    if c == bt_rcv:              
                        n.append(str(ax) + str(bx))           
                        x = True
                        break
                    else:
                        None
                    bx += 1
                if x == True: break
                ax += 1            
            if x == True: break    
        if counter == 3: 
            out.append(int(d.join(n),2))
            # Reset variable
            counter = 0 
            n = []
        else: 
            counter += 1
            
    rcv_img = np.reshape(np.array(out), (128,128))
    cv2.imwrite('recover.png',rcv_img)
    
    print("Decrypted!")
    return ''

def Embed_Eval_Code_S():
    current_path = os.getcwd()
    #Read the image
    cvr_img = cv2.imread(current_path + 'Lena.Png',0) #0 = GRAYSCALE, 1 = COLOR     
    cvr_img = cv2.resize(cvr_img, (256,256))

    # msg_img = cv2.imread(args["message_image"],0)
    msg_img = cv2.imread(current_path + 'Star.Png',0)
    msg_img = cv2.resize(msg_img, (128,128))
    
    xbox_table = XBOX_Generate(0)
        
    # Flatten Image
    cvr_flatten = cvr_img.flatten()
    msg_flatten = msg_img.flatten()
    out = []
        
    # Split x into 4 part (2-Bit each), Map with XOR_XBOX
    m_out = []
    k_out = []

    counter = 0
    for m in msg_flatten:
        m = np.binary_repr(m, width=8)        
        b = np.array([0,0,0,0])    
        loop = range(4) 
        counter = 0
        for y in loop:            
            count_multiply = counter*2                       
            bx = m[count_multiply]
            by = m[count_multiply+1]    
            if bx == '0' and by == '0':
                b[counter] = xbox_table[counter,0,0]
            elif bx == '0' and by == '1':
                b[counter] = xbox_table[counter,1,0]
            elif bx == '1' and by == '0':
                b[counter] = xbox_table[counter,0,1]       
            else:
                b[counter] = xbox_table[counter,1,1]              
            m_out.append(b[counter])  
            counter += 1
            
    counter = 0
    for c in cvr_flatten:        
        c = np.binary_repr(c, width=8)
        
        XOR_a = c[-4:]
        XOR_b = np.binary_repr(m_out[counter], width=4)  
            
        XOR_rst = int(XOR_a,2) ^ int(XOR_b,2)
        XOR_key = int(XOR_a,2)
        
        k_out.append(XOR_key)
                    
        bt_a = c[:4]   
        bt_b = str(bin(XOR_rst)[2:].zfill(len(bt_a)))
        bt_rep = int((bt_a + bt_b),2)
        
        out.append(bt_rep)
        counter += 1

    stg_img = np.reshape(np.array(out), (256,256))    

    # Convert back to 2D Array for output_path.csv
    xbox_table2D = np.reshape(xbox_table, (-1,2))         
        
    cv2.imwrite(current_path + 'Stego.Png', stg_img)    
    np.savetxt(current_path + '_xKey.csv', k_out, delimiter=",",fmt='%s')
    np.savetxt(current_path + '_xKeyTable.csv', xbox_table2D, delimiter=",", fmt='%s')

def Embed_Eval_Code_SE():
    current_path = os.getcwd()
    message_key = 'this is password'
    hex_key = Process_Key(Str2Hex(message_key))               
    # Generate xbox table as cipher key
    xbox_flat = XBOX_Generate(1)                
    xbox_table = np.reshape(xbox_flat, (-1,2,2))
                
    temp = ''   
    for i in xbox_flat:           
        temp = temp + binascii.hexlify(i).decode()[:2]        
                
    _cp_key = SubBytes(Process_Key(temp))
    cp_key = KeyExpansion(_cp_key,4,4,10)
    encrypt_table = Cipher(hex_key,cp_key,4,4,10)                
    cipher_xbox_table = np.reshape(encrypt_table, (-1,2,2))                
        
    #Read the image
    cvr_img = cv2.imread(current_path + 'Lena.Png',0) #0 = GRAYSCALE, 1 = COLOR     
    cvr_img = cv2.resize(cvr_img, (256,256))

    # msg_img = cv2.imread(args["message_image"],0)
    msg_img = cv2.imread(current_path + 'Star.Png',0)
    msg_img = cv2.resize(msg_img, (128,128))
        
    # Flatten Image
    cvr_flatten = cvr_img.flatten()
    msg_flatten = msg_img.flatten()
    out = []
        
    # Split x into 4 part (2-Bit each), Map with XOR_XBOX
    m_out = []
    k_out = []

    counter = 0
    for m in msg_flatten:
        m = np.binary_repr(m, width=8)        
        b = np.array([0,0,0,0])    
        loop = range(4) 
        counter = 0
        for y in loop:            
            count_multiply = counter*2                       
            bx = m[count_multiply]
            by = m[count_multiply+1]    
            if bx == '0' and by == '0':
                b[counter] = xbox_table[counter,0,0]
            elif bx == '0' and by == '1':
                b[counter] = xbox_table[counter,1,0]
            elif bx == '1' and by == '0':
                b[counter] = xbox_table[counter,0,1]       
            else:
                b[counter] = xbox_table[counter,1,1]              
            m_out.append(b[counter])  
            counter += 1
            
    counter = 0
    for c in cvr_flatten:        
        c = np.binary_repr(c, width=8)
        
        XOR_a = c[-4:]
        XOR_b = np.binary_repr(m_out[counter], width=4)  
            
        XOR_rst = int(XOR_a,2) ^ int(XOR_b,2)
        XOR_key = int(XOR_a,2)
        
        k_out.append(XOR_key)
                    
        bt_a = c[:4]   
        bt_b = str(bin(XOR_rst)[2:].zfill(len(bt_a)))
        bt_rep = int((bt_a + bt_b),2)
        
        out.append(bt_rep)
        counter += 1

    stg_img = np.reshape(np.array(out), (256,256))    

    # Convert back to 2D Array for output.csv
    xbox_table2D = np.reshape(cipher_xbox_table, (-1,2))       
    np.savetxt(current_path + '_xKeySE.csv', _cp_key, delimiter=",", fmt='%s')
        
    cv2.imwrite('stego.png', stg_img)    
    np.savetxt(current_path + '_xKey.csv', k_out, delimiter=",",fmt='%s')
    np.savetxt(current_path + '_xKeyTable.csv', xbox_table2D, delimiter=",", fmt='%s')
                
def Extract_Eval_Code_S():
    current_path = os.getcwd()
    # read the stego image
    stg_img = cv2.imread(current_path + 'Stego.Png',0)
    stg_img = cv2.resize(stg_img, (256,256))

    # flatten the pixel into binary
    stg_flatten = stg_img.flatten()
    out = []
    
    # Key Reference for BitXOR
    with open(current_path + '_xKey.csv', newline='') as csvfile:
            xbox_key = list(csv.reader(csvfile,delimiter=','))
    
    with open(current_path + '_xKeyTable.csv', newline='') as csvfile:
        xbox_table2D = list(csv.reader(csvfile,delimiter=','))
        xbox_table = Convert2D_To_3D(xbox_table2D)        
        
    # Initialize Variable
    d = '' # Delimiter
    counter = 0
    key_count = 0
    n = []
    for m in stg_flatten:    
        m = np.binary_repr(m, width=8)
        # retrieve the last 4 bits and refer to xbox_table and reverse the process
        x = False # Boolean to check values found
              
        XOR_a = m[-4:]      
        XOR_b = np.binary_repr(Float2Int(xbox_key[key_count][0]), width=4)
        bt_rcv = int(XOR_a,2) ^ int(XOR_b,2)

        key_count += 1
        for a in xbox_table:       
            ax = 0 
            for b in a:                               
                bx = 0
                for c in b:                   
                    if c == bt_rcv:              
                        n.append(str(ax) + str(bx))           
                        x = True
                        break
                    else:
                        None
                    bx += 1
                if x == True: break
                ax += 1            
            if x == True: break    
        if counter == 3: 
            out.append(int(d.join(n),2))
            # Reset variable
            counter = 0 
            n = []
        else: 
            counter += 1
            
    rcv_img = np.reshape(np.array(out), (128,128))
    cv2.imwrite(current_path + 'Recover.Png',rcv_img)
 
def Extract_Eval_Code_SE():
    current_path = os.getcwd()
    message_key = 'this is password'
    pass_key = Process_Key(Str2Hex(message_key))               
                
    # Generate xbox table as cipher key
    with open(current_path + '_xKeyTable.csv', newline='') as csvfile:
        dc_table = list(csv.reader(csvfile,delimiter=','))                
        dc_table = np.reshape(dc_table, (-1,4))                    
                          
    with open(current_path + '_xKeySE.csv', newline='') as csvfile:
        _dc_key = list(csv.reader(csvfile,delimiter=','))                   
        for j, pre_key in enumerate(_dc_key):
            for i, nest_key in enumerate(pre_key):
                _dc_key[i][j] = int(_dc_key[i][j])
        dc_key = KeyExpansion(_dc_key,4,4,10)
        
    decrypt_table = InvCipher(dc_table,dc_key,4,4,10)              
    
    decipher_xbox_table = np.reshape(decrypt_table, (-1,2,2))                
    decipher_xbox_table = Inv_XBOX(Inv_Process_Key(InvSubBytes(_dc_key)))
    decipher_xbox_table = np.reshape(decipher_xbox_table, (-1,2,2))
    
    xbox_table = decipher_xbox_table
    # read the stego image
    stg_img = cv2.imread(current_path + 'Stego.Png',0)
    stg_img = cv2.resize(stg_img, (256,256))

    # flatten the pixel into binary
    stg_flatten = stg_img.flatten()
    out = []
    
    # Key Reference for BitXOR
    with open(current_path + '_xKey.csv', newline='') as csvfile:
            xbox_key = list(csv.reader(csvfile,delimiter=','))
        
    # Initialize Variable
    d = '' # Delimiter
    counter = 0
    key_count = 0
    n = []
    for m in stg_flatten:    
        m = np.binary_repr(m, width=8)
        # retrieve the last 4 bits and refer to xbox_table and reverse the process
        x = False # Boolean to check values found
              
        XOR_a = m[-4:]      
        XOR_b = np.binary_repr(Float2Int(xbox_key[key_count][0]), width=4)
        bt_rcv = int(XOR_a,2) ^ int(XOR_b,2)

        key_count += 1
        for a in xbox_table:       
            ax = 0 
            for b in a:                               
                bx = 0
                for c in b:                   
                    if c == bt_rcv:              
                        n.append(str(ax) + str(bx))           
                        x = True
                        break
                    else:
                        None
                    bx += 1
                if x == True: break
                ax += 1            
            if x == True: break    
        if counter == 3: 
            out.append(int(d.join(n),2))
            # Reset variable
            counter = 0 
            n = []
        else: 
            counter += 1
            
    rcv_img = np.reshape(np.array(out), (128,128))
    cv2.imwrite(current_path + 'Recover.Png',rcv_img)
    
def Evaluation_Prg(iteration_list,function,mode):
    ite_array = np.array(iteration_list.split(','))
    
    eval = []
    eval = ['Iteration','Exec_Time/Loop','Total_Exec_Time(sec)', 'Total_Exec_Time(min)']
    for i in ite_array:
        i = int(i)
        if function == '2':
            if mode == 'S':
                elapsed_time = timeit.timeit(Embed_Eval_Code_S, number=i)        
            else: 
                elapsed_time = timeit.timeit(Embed_Eval_Code_SE, number=i) 
        else:
            if mode == 'S':
                elapsed_time = timeit.timeit(Extract_Eval_Code_S, number=i)   
            else:
                elapsed_time = timeit.timeit(Extract_Eval_Code_SE, number=i)   
        eval.append(i)
        eval.append(elapsed_time/i)
        eval.append(elapsed_time)
        eval.append(elapsed_time / 60)

        print("Total execution time for " + str(i) + " loop: " + str(round(elapsed_time,2)) + " seconds / " + str(round(elapsed_time/60,2)) + " minutes")
        print("Execution time per loop: " + str(elapsed_time/i) + " seconds")
    eval = np.reshape(eval, (-1,4))
    if function == '2':
        if mode == 'S':
            np.savetxt(current_path + 'Evaluation_Result_S.csv', eval, delimiter=",",fmt='%s')
        else:
            np.savetxt(current_path + 'Evaluation_Result_SE.csv', eval, delimiter=",",fmt='%s')
    else:
        if mode == 'S':
            np.savetxt(current_path + 'Evaluation_Result_XS.csv', eval, delimiter=",",fmt='%s')
        else:
            np.savetxt(current_path + 'Evaluation_Result_XSE.csv', eval, delimiter=",",fmt='%s')
if __name__ == '__main__':
    Main()