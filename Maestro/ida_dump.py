import idaapi

# Prompt the user to select a file
selected_file = idaapi.ask_file(0, "*.*", "Please select a file")

if selected_file:
    print("Selected file:", selected_file)
else:
    print("No file selected or operation cancelled by the user")


def get_bytes(start_ea, size):
    byte_array = bytearray()
    for ea in range(start_ea, start_ea + size):
        byte_value = idaapi.get_byte(ea)
        if byte_value == -1:
            print("Error reading byte at address 0x{:X}".format(ea))
            break
        byte_array.append(byte_value)
    return byte_array


address = 0xc025e000
size = 0x1000
dbgr = False
with open(selected_file, "wb") as out:
    data = get_bytes(address, size)
    out.write(data)
print(f"Dumped from {hex(address)} to {hex(address+size)}")
