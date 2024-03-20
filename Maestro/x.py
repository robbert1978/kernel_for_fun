# Read the binary file
with open("dump", "rb") as f:
    binary_data = f.read()

# Convert binary data to a list of byte values
byte_values = [hex(byte) for byte in binary_data]


nasm_syntax = "db " + ", ".join(byte_values)

# Print or write NASM syntax to a file
print(nasm_syntax)
