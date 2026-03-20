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
    def embed_lsb_332(r: int, g: int, b: int, message_byte: int) -> tuple:
        # Pecah byte pesan sesuai skema 3-3-2:
        # R = 3 bit, G = 3 bit, B = 2 bit
        r_bits = (message_byte >> 5) & 0b111
        g_bits = (message_byte >> 2) & 0b111
        b_bits = message_byte & 0b011
        
        # Hapus LSB lama dan timpa sama bit modifikasi
        new_r = (r & 0xF8) | r_bits
        new_g = (g & 0xF8) | g_bits
        new_b = (b & 0xFC) | b_bits
        
        return new_r, new_g, new_b

    @staticmethod
    def extract_lsb_332(r: int, g: int, b: int) -> int:
        r_bits = r & 0b111
        g_bits = g & 0b111
        b_bits = b & 0b011
        
        # Shift & gabungin balik jadi 1 byte utuh
        message_byte = (r_bits << 5) | (g_bits << 2) | b_bits
        return message_byte


class A51Cipher:
    def __init__(self, key: str):
        # Format key ke 64-bit (8 bytes) untuk state awal
        if len(key) < 8:
            key = key.ljust(8, '0')
        elif len(key) > 8:
            key = key[:8]
        
        self.key_bits = BitManipulator.bytes_to_bits(key.encode('utf-8'))[:64]
        
    def _majority(self, x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)
        
    def _generate_keystream_block(self, frame_number: int) -> list:
        # Papan LFSR 19, 22, dan 23 bit
        R1 = [0] * 19
        R2 = [0] * 22
        R3 = [0] * 23
        
        fn_bits = []
        for i in range(21, -1, -1):
            fn_bits.append((frame_number >> i) & 1)
            
        # 1. Key setup (64 putaran)
        for i in range(64):
            t1 = R1[13] ^ R1[16] ^ R1[17] ^ R1[18] ^ self.key_bits[i]
            t2 = R2[20] ^ R2[21] ^ self.key_bits[i]
            t3 = R3[7] ^ R3[20] ^ R3[21] ^ R3[22] ^ self.key_bits[i]
            
            R1.pop(); R1.insert(0, t1)
            R2.pop(); R2.insert(0, t2)
            R3.pop(); R3.insert(0, t3)
            
        # 2. Frame number setup (22 putaran)
        for i in range(22):
            t1 = R1[13] ^ R1[16] ^ R1[17] ^ R1[18] ^ fn_bits[i]
            t2 = R2[20] ^ R2[21] ^ fn_bits[i]
            t3 = R3[7] ^ R3[20] ^ R3[21] ^ R3[22] ^ fn_bits[i]
            
            R1.pop(); R1.insert(0, t1)
            R2.pop(); R2.insert(0, t2)
            R3.pop(); R3.insert(0, t3)
            
        # 3. Mixing tanpa output (100 putaran max, ambil majority-nya)
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
                
        # 4. Keystream keluaran asli
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
        # Flow A5/1 (en/de-cryption murni main di XOR doang)
        data_bits = BitManipulator.bytes_to_bits(data)
        out_bits = []
        
        # Potong-potong per 228 bit blok payload 
        blocks = [data_bits[i:i + 228] for i in range(0, len(data_bits), 228)]
        
        for fn, block in enumerate(blocks):
            keystream = self._generate_keystream_block(fn)
            for i in range(len(block)):
                out_bits.append(block[i] ^ keystream[i])
                
        return BitManipulator.bits_to_bytes(out_bits)
