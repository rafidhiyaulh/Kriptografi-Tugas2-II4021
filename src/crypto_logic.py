class BitManipulator:
    @staticmethod
    def bytes_to_bits(data: bytes) -> list:
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def bits_to_bytes(bits: list) -> bytes:
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
                else:
                    byte = byte << 1
            byte_array.append(byte)
        return bytes(byte_array)

    @staticmethod
    def embed_lsb(r, g, b, message_byte, r_bits, g_bits, b_bits):
        if r_bits + g_bits + b_bits != 8:
            raise ValueError("Total bit R+G+B harus berjumlah 8 bit per piksel")

        r_val = (message_byte >> (g_bits + b_bits)) & ((1 << r_bits) - 1)
        g_val = (message_byte >> b_bits) & ((1 << g_bits) - 1)
        b_val = message_byte & ((1 << b_bits) - 1)

        new_r = (int(r) & (~((1 << r_bits) - 1) & 0xFF)) | r_val
        new_g = (int(g) & (~((1 << g_bits) - 1) & 0xFF)) | g_val
        new_b = (int(b) & (~((1 << b_bits) - 1) & 0xFF)) | b_val
        
        return new_r, new_g, new_b

    @staticmethod
    def extract_lsb(r: int, g: int, b: int, r_bits: int, g_bits: int, b_bits: int) -> int:
        r_val = r & ((1 << r_bits) - 1)
        g_val = g & ((1 << g_bits) - 1)
        b_val = b & ((1 << b_bits) - 1)

        return (r_val << (g_bits + b_bits)) | (g_val << b_bits) | b_val


class A51Cipher:
    def __init__(self, key: str):
        if len(key) < 8:
            key = key.ljust(8, '0')
        elif len(key) > 8:
            key = key[:8]
        
        self.key_bits = BitManipulator.bytes_to_bits(key.encode('utf-8'))[:64]
        
    def _majority(self, x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)
        
    def _generate_keystream_block(self, frame_number: int) -> list:
        R1 = [0] * 19
        R2 = [0] * 22
        R3 = [0] * 23
        
        fn_bits = []
        for i in range(21, -1, -1):
            fn_bits.append((frame_number >> i) & 1)
            
        for i in range(64):
            t1 = R1[13] ^ R1[16] ^ R1[17] ^ R1[18] ^ self.key_bits[i]
            t2 = R2[20] ^ R2[21] ^ self.key_bits[i]
            t3 = R3[7] ^ R3[20] ^ R3[21] ^ R3[22] ^ self.key_bits[i]
            
            R1.pop(); R1.insert(0, t1)
            R2.pop(); R2.insert(0, t2)
            R3.pop(); R3.insert(0, t3)
            
        for i in range(22):
            t1 = R1[13] ^ R1[16] ^ R1[17] ^ R1[18] ^ fn_bits[i]
            t2 = R2[20] ^ R2[21] ^ fn_bits[i]
            t3 = R3[7] ^ R3[20] ^ R3[21] ^ R3[22] ^ fn_bits[i]
            
            R1.pop(); R1.insert(0, t1)
            R2.pop(); R2.insert(0, t2)
            R3.pop(); R3.insert(0, t3)
            
        for _ in range(100):
            maj = self._majority(R1[8], R2[10], R3[10])
            
            if R1[8] == maj:
                t1 = R1[13] ^ R1[16] ^ R1[17] ^ R1[18]
                R1.pop(); R1.insert(0, t1)
            if R2[10] == maj:
                t2 = R2[20] ^ R2[21]
                R2.pop(); R2.insert(0, t2)
            if R3[10] == maj:
                t3 = R3[7] ^ R3[20] ^ R3[21] ^ R3[22]
                R3.pop(); R3.insert(0, t3)
                
        keystream = []
        for _ in range(228):
            maj = self._majority(R1[8], R2[10], R3[10])
            
            if R1[8] == maj:
                t1 = R1[13] ^ R1[16] ^ R1[17] ^ R1[18]
                R1.pop(); R1.insert(0, t1)
            if R2[10] == maj:
                t2 = R2[20] ^ R2[21]
                R2.pop(); R2.insert(0, t2)
            if R3[10] == maj:
                t3 = R3[7] ^ R3[20] ^ R3[21] ^ R3[22]
                R3.pop(); R3.insert(0, t3)
            
            keystream.append(R1[18] ^ R2[21] ^ R3[22])
            
        return keystream

    def process(self, data: bytes) -> bytes:
        data_bits = BitManipulator.bytes_to_bits(data)
        out_bits = []
        
        blocks = [data_bits[i:i + 228] for i in range(0, len(data_bits), 228)]
        
        for fn, block in enumerate(blocks):
            keystream = self._generate_keystream_block(fn)
            for i in range(len(block)):
                out_bits.append(block[i] ^ keystream[i])
                
        return BitManipulator.bits_to_bytes(out_bits)
