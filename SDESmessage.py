##### SDES #####
#The Simple DES algorithms functions very similarly to the DES, but with a considerably smaller tablem key and plaintext sizes.

#Reference tables that are used for rearranging the bits of the key and the plaintext
#Permutation tables, 10,8 and 4 bits
tabP10=(2,4,1,6,3,9,0,8,7,5)
tabP8=(5,2,6,3,7,4,9,8)
tabP4=(1,3,2,0)

tabIP=(1,5,2,0,3,7,4,6) #Initial Permutation (called at the BEGGINING of the encryption/decryption)
tabIP_inv=(3,0,2,4,6,1,7,5) #Inverse of Initial Permutation (called at the END of the encryption/decryption)
tabEP=(3,0,1,2,1,2,3,0) #Expanded Permutation (transforms 4 bits into 8 bits)


#S boxes                #Bits are used as coordinates in the table
tabS0=([1,0,3,2],
       [3,2,1,0],
       [0,2,1,3],
       [3,1,3,2])

tabS1=([0,1,2,3],
       [2,0,1,3],
       [3,0,1,0],
       [2,1,0,3])



#Functions  #Most are self explanatory

def decimalToBinary(i):
    return [int(b) for b in f"{i:02b}"]

#Left shift #shifts the bits to the left by a desired distance(e.g., 11011110 -> 10111101)
def leftshift(list,distance): 
  templist=[]
  for i in range(distance,len(list)):
    templist.append(list[i])
  for i in range(0,distance):
    templist.append(list[i])
  return(templist)

#Permutation #Rearranges the bits of a list according to a desired table (except S-boxes)
def permutation(list,table): 
  templist=[]
  for i in table:
    templist.append(list[i])
  return templist

#Divide in 2 halves, mainly used for the switch, which switches the left and right halves of the plaintext (e.g., 11110000 -> 00001111)
def divide(list):
    leftList = []
    rightList = []
    for i in range(int(len(list)/2)):
        leftList.append(list[i])
    for i in range(int(len(list)/2),len(list)):
        rightList.append(list[i])
    return([leftList,rightList])

def xor(listA, listB):
  templist = []
  for i in range(len(listA)):
    templist.append(listA[i]^listB[i])
  return templist

#S-boxes #Takes a list of 4 bits, and returns a list of 4 bits shuffled by using the bits as coordinates to the S-boxes (1st,3rd bits are the row, 2nd,4th bits are the column)
def sBox(lists):
  sideL,sideR = lists[0],lists[1]
  sideL = [int(f"{sideL[0]}{sideL[3]}",2), int(f"{sideL[1]}{sideL[2]}",2)]#[row,column]
  sideR = [int(f"{sideR[0]}{sideR[3]}",2), int(f"{sideR[1]}{sideR[2]}",2)]
  sideL = tabS0[(sideL[0])][(sideL[1])]
  sideR = tabS1[(sideR[0])][(sideR[1])]
  return (decimalToBinary(sideL) + decimalToBinary(sideR))

#Key generator #Generates the 2 keys used in the encryption/decryption, the input is the 10bit key, and the output are 2 8bit keys
#The order of the 8 bit keys is what differentiantes the encryption from the decryption
def keysgenerator(k10):
  keys = []
  templist = permutation(k10,tabP10)
  templist = divide(templist)
  templist = [leftshift(templist[0],1),leftshift(templist[1],1)]
  keys.append(permutation((templist[0] + templist[1]),tabP8)) #Key 1
  templist = [leftshift(templist[0],2),leftshift(templist[1],2)]
  keys.append(permutation((templist[0] + templist[1]),tabP8)) #Key 2
  return keys

#This function is for the sake of brevity and readability, it is called twice in the encryption/decryption functions
def round(key,plainText):
  templist = divide(plainText)
  sideL,sideR = templist[0],templist[1]
  templist = permutation(sideR,tabEP)
  templist = xor(key,templist)
  templist = sBox(divide(templist))
  templist = xor(sideL,permutation(templist,tabP4))
  return templist + sideR


#this is the actual encryption/decryption process, which calls the keysgenerator and round functions
def process(keys,plainText):
  templist = permutation(plainText,tabIP)#First, the initial permutation is applied to the plaintext

  templist = round(keys[0],templist) #First round using the first key

  templist = divide(templist)
  templist = templist[1] + templist[0] #This is the switch

  templist = round(keys[1],templist) #Second round using the second key

  return permutation(templist,tabIP_inv) #Lastly, the inverse of the initial permutation is applied to the plaintext, returning the result


#This guarantees the order of the keys, by reversing the order of the keys, you can "undo" the encryption, and decrypt the text
def run(plainText, key10, type):
   keys = keysgenerator(key10)
   if type == "2":  # Decryption
      keys = [keys[1], keys[0]]
   result = []
   for i in plainText:
      result.append(process(keys, i))
   return result


##### input ##### #Transforms the inputs for the functions, and makes the output readable for the user. Unecessary to go into detail
def textStringToBytesList(inputString):
    asciiCharsList = []
    for i in inputString:
        tempChar = format(ord(i),'08b')
        asciiCharsList.append([int(bit) for bit in (tempChar)])

    return asciiCharsList

def bytesListToTextString(inputList):
    byteString = tempByte = ""
    for i in inputList:
        for j in i:
            tempByte = tempByte + str(j)
        byteString = byteString + chr(int(tempByte,2))
        tempByte = ""

    return byteString

def binaryStringToList(inputString,size):
    finalList = []
    tempList = []
    k=0
    for i in inputString:
        k+=1
        tempList.append(int(i))
        if k == size:
            finalList.append(tempList)
            tempList = []
            k=0
    return finalList

def bytesListToBinaryString(inputList):
    byteString = tempByte = ""
    for i in inputList:
        for j in i:
            tempByte = tempByte + str(j)
        byteString = byteString + tempByte
        tempByte = ""

    return byteString


##### main ##### #Just the main function, to gather the user's inputs and call the functions
def main():
  operationChoice = sizeChoice = ''
  question = "\n1- Encrypt\n2- Decrypt\n(1/2): "
  while True:
    answer = input(question)
    if ((answer =='1' or answer == '2') and operationChoice == ''):
      operationChoice = answer
      answer = ""
      question = "\n1- Text (e.g., 'Hello World!')   \n2- Byte(e.g., '01001101')\n(1/2): "
    elif ((answer == '1' or answer == '2') and sizeChoice == ''):
      sizeChoice = answer
      answer = ""   
      question = ""
      break
    else:
       print("Invalid input, try again:")

  if sizeChoice == '1':
     size = ["text", "Hello World!"]
  elif sizeChoice == '2':
     size = ["byte", "01001101. 8 bits at a time, any more will be ignored, any less it won't work)"] 
  while True:  
    inputKey = input("Insert your 10-bit key, leave blank for default(e.g., '1001011010')\ninput: ")
    if inputKey == "":
      inputKey = "1010000010"
      break
    elif (any(i not in '01' for i in inputKey) or len(inputKey) != 10):
      print("Invalid key, Try again")
    else:
      break 

  if operationChoice == '1':
     question = f"Insert your {size[0]} for encryption(e.g.,{size[1]}):\ninput:  "
  elif operationChoice == '2':
     question = f"Insert your encrypted {size[0]} for decryption(e.g.,{size[1]}):\ninput: "
  inputPlainText = input(question)

  if (sizeChoice == '1'and operationChoice == '1'):
     processedPlainText = textStringToBytesList(inputPlainText)
  else:
     processedPlainText = binaryStringToList(inputPlainText,8)
  
  result = run(processedPlainText,binaryStringToList(inputKey,10)[0],operationChoice)
  if (operationChoice == '1' or sizeChoice == '2'):
     result = bytesListToBinaryString(result)
  elif (operationChoice == '2'):
     result = bytesListToTextString(result)

  print(f"""
        Key: {inputKey} 
        Original PlainText: {inputPlainText}
        {["Encrypted", "Decrypted"][int(operationChoice)-1]} Text: {result}
        """)

main()
