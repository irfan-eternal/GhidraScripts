from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def decrypter(data_string, data_key):
    decoded = ''
     for i in xrange(0, len(data_string):
         decoded += chr((data_string[i]) ^ (data_key[i % len(data_key)]))
         return decoded


enc_address_start = askAddress("Provide Address of Encrypred String", "Address")
enc_address_end  = find(enc_address_start, [00, 00]) 
len_address = int(str(enc_address_end), 16) - int(str(enc_address_start), 16)
data =  getBytes(enc_address_start, len_address) 
key_address_start = askAddress("Provide Address of Key String", "Address")
key_address_end = find(key_address_start, [00, 00])
len_address_key = int(str(key_address_end), 16) - int(str(key_address_start), 16) 
key = b''
key = getBytes(key_address_start, len_address_key)
global decoded
decoded = decrypter(data, key)
mw_decrypt = askAddress("Provide Address of decrypt function", "Address")
refs =  getReferencesTo(mw_decrypt)
options = DecompileOptions() 
monitor = ConsoleTaskMonitor()
ifc = DecompInterface() 
ifc.setOptions(options)
ifc.openProgram(currentProgram)
for xref in refs:
    i = xref.getFromAddress()
    func = getFunctionContaining(i)
    res =  ifc.decompileFunction( func, 60, monitor)
    high_func = res.getHighFunction() 
    pcodeops = high_func.getPcodeOps(i)
    op = pcodeops.next() 
    print(str(i))
    param = op.getInputs()
    offset = str(param[1]).split(",")
    offset_1 = offset[1]
    offset_int = int(offset_1.lstrip(), 16) 
    decrypted_string = decoded[offset_int:].split("\x00")[0]
    print(decrypted_string)
    setEOLComment (i, decrypted string)
