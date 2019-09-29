def swap(msg, seq):
    sw = ""
    for i in seq:
        sw += msg[i - 1]
    return sw

def extend(msg, nB=8):
    ext = str(bin(msg))
    ext = ext[2:len(ext)]  # only select after 0b
    extmp = ""
    for i in range(nB - len(ext)):  # loop for adding 0 until full
        extmp = extmp + "0"
    ext = extmp + ext
    return ext

def SBox(msg):
    S0 = [["01", "00", "11", "10"], ["11", "10", "01", "00"], ["00", "10", "01", "11"], ["11", "01", "11", "10"]]
    S1 = [["00", "01", "10", "11"], ["10", "00", "01", "11"], ["11", "00", "01", "00"], ["10", "01", "00", "11"]]

    first4Bit = msg[0:4]
    last4Bit = msg[4:8]

    row = int(first4Bit[0] + first4Bit[3], base=2)
    col = int(first4Bit[1] + first4Bit[2], base=2)

    r_S0 = S0[row][col]

    row = int(last4Bit[0] + last4Bit[3], base=2)
    col = int(last4Bit[1] + last4Bit[2], base=2)

    r_S1 = S1[row][col]

    return r_S0 + r_S1

def SDEScrack(msg, sk1, sk2):

    # step1 ip from cipher
    s1_Msg = extend(msg)  # firstly extend
    defSeqIP = [2, 6, 3, 1, 4, 8, 5, 7]  # ip default
    st1 = swap(s1_Msg, defSeqIP)  # swap with ip default
    ####################################################

    # step2 ep
    s2_Msg = st1[4:8]  # select only 4 bit on the right
    defSeqEP = [4, 1, 2, 3, 2, 3, 4, 1]  # ep default
    st2 = swap(s2_Msg, defSeqEP)  # swap with ep default
    ####################################################

    # step3 xor with k2
    st3 = ""
    key_st2 = extend(sk2)  # extend subKey 2

    for i in range(len(key_st2)):
        st3 = st3 + str(int(st2[i]) ^ int(key_st2[i]))
    ####################################################

    # step4 SBox
    st4 = SBox(st3)
    ####################################################

    # step5 P4
    defSeqP4 = [2, 4, 3, 1]
    st5 = swap(st4, defSeqP4)
    ####################################################

    # step6 xor first 4 bit of step 1 with step5
    st6 = ""
    tmp1 = st1[0:4]
    for i in range(len(tmp1)):
        st6 = st6 + str(int(tmp1[i]) ^ int(st5[i]))
    ####################################################

    # step7 replace first 4 bit of step 1 with step 6
    st7 = st6 + st1[4:8]
    ####################################################

    # step8 separate step7 into half and swap them
    defHalfSwap = [5, 6, 7, 8, 1, 2, 3, 4]
    st8 = swap(st7, defHalfSwap)
    ####################################################

    # step9 ep last 4 bit of step 8
    s9_Msg = st8[4:8]  # select only 4 bit on the right
    st9 = swap(s9_Msg, defSeqEP)  # swap with ep default
    ####################################################

    # step10 xor with sub key 1
    st10 = ""
    key_st10 = extend(sk1)  # extend subKey 1
    for i in range(len(key_st10)):
        st10 = st10 + str(int(st9[i]) ^ int(key_st10[i]))
    ####################################################

    # step11 SBox of step10
    st11 = SBox(st10)
    ####################################################

    # step12 p4 of step11
    st12 = swap(st11, defSeqP4)
    ####################################################

    # step13 xor step12 with first 4 bit of step8
    st13 = ""
    tmp2 = st8[0:4]
    for i in range(len(tmp2)):
        st13 = st13 + str(int(st12[i]) ^ int(tmp2[i]))
    ####################################################

    # step14 replace first 4 bit of step 8 with step 13
    st14 = st13 + st8[4:8]
    ####################################################

    # step15 inverse of step14
    defSeqInv = [4, 1, 3, 5, 7, 2, 8, 6]
    st15 = swap(st14, defSeqInv)
    ####################################################

    return st15

def findSubKey(ci, text):

    subkey = []  # list for keeping subKeys

    for j in range(256):  # 0-255 = 256
        subkey1 = j

        for k in range(256):
            subkey2 = k

            for msg in range(len(ci)):
                test = SDEScrack(ci[msg], subkey1, subkey2)  # start decrypting

                if int(test, base=2) != int(text[msg]):  # check if match with student id number
                    break
                if msg == len(ci) - 1:  # check until last digit of student id if its come to last digit then it was all matched
                    subkey.append(subkey1)
                    subkey.append(subkey2)
                    return subkey

    print("Key not found")
    return None

def P10(k):
    defSeqP10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    return swap(k, defSeqP10)

def circularShift(k, nB):
    if nB == 1:
        defSeqRotate = [1, 2, 3, 4, 0]
    if nB == 3:
        defSeqRotate = [3, 4, 0, 1, 2]
    return swap(k, defSeqRotate)

def P8(k):
    defSeqP8 = [6, 3, 7, 4, 8, 5, 10, 9]
    return swap(k, defSeqP8)

def getKey(sk1, sk2):
    for i in range(1024):  # 10 bit key: 2^10
        key = extend(i, 10)  # 10 bit str output
        k_st1 = P10(key)

        k_st2 = str(circularShift(k_st1[0:5], 1)) + str(circularShift(k_st1[5:10], 1)) # subkey 1 shift 1 bit
        k1 = P8(k_st2)

        k_st2 = str(circularShift(k_st1[0:5], 3)) + str(circularShift(k_st1[5:10], 3)) # subkey 2 shift 3 bit
        k2 = P8(k_st2)

        if int(k1, base=2) == sk1 and int(k2, base=2) == sk2 or int(k1, base=2) == sk2 and int(k2, base=2) == sk1:
            return key

    ##########################################################################

# main starts here

# student id
studentID = "590610622"
studentID = studentID.encode('utf-8')

# my cipher text from website
cipher = [0b101000,0b11,0b10111000,0b1110111,0b1001101,0b10111000,0b1110111,0b110110,0b110110,0b1001101,
          0b1001101,0b10111000,0b11,0b10100011,0b10111000,0b110110,0b1110111,0b11010111,0b1001101,0b1110111,
          0b10111000,0b101000,0b11111001,0b1001101,0b110,0b1110111,0b10111000,0b1110111,0b10100011,0b11010111,
          0b11111001,0b1001101,0b10111000,0b101000,0b11010111,0b10100011,0b1110111,0b11111001,0b110,0b110110,
          0b1001101,0b11010111,0b101000,0b10100011,0b101000,0b110110,0b10111000,0b10111000,0b110110,0b101000,
          0b10100011,0b11,0b1110111,0b11010111,0b1110111,0b11,0b1110111,0b1110111,0b110110,0b10100011,
          0b110,0b110110,0b1001101,0b11,0b11111001,0b11,0b1110111,0b1001101,0b10111000,0b11,
          0b10100011,0b101000,0b1110111,0b1001101,0b11010111,0b110110,0b11010111]

sub_keys = []
sub_keys = findSubKey(cipher[0:9], studentID)

key = getKey(sub_keys[0], sub_keys[1])

print("Key : " + str(key))

ans = []
print("Decrypted Result : ")
for i in range(len(cipher)):
    ans = int(SDEScrack(cipher[i], sub_keys[0], sub_keys[1]), base=2)
    print(chr(ans), end=' ')

    ##########################################################################