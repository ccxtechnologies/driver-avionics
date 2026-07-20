import struct
import time

# 1. Define the 22-byte Packet Header
time_msecs = int(time.time() * 1000)
status = 0
count = 1
width = 4  # 4 bytes per ARINC-717 word
length = 12  # 3 words * 4 bytes each = 12 bytes of payload

# Pack the header (Little Endian: long long, uint, ulong long, uchar, uchar)
header = struct.pack('<qIQBB', time_msecs, status, count, width, length)

# 2. Define the ARINC-717 Data Words
# Format: (Word << 16) | (Word Count << 3) | Subframe
word1 = (0xABC << 16) | (1 << 3) | 0  # Subframe 0, Word 1, Data: 0xABC
word2 = (0x123 << 16) | (2 << 3) | 0  # Subframe 0, Word 2, Data: 0x123
word3 = (0x456 << 16) | (3 << 3) | 0  # Subframe 0, Word 3, Data: 0x456

# Pack the payload (3 unsigned ints)
payload = struct.pack('<III', word1, word2, word3)

# 3. Write to file
with open('test_data.bin', 'wb') as f:
    f.write(header + payload)

print("Created test_data.bin!")
