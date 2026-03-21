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
    def embed_lsb(r: int, g: int, b: int, message_byte: int, mode="332") -> tuple:
        if mode == "332":
            r_bits = (message_byte >> 5) & 0b111
            g_bits = (message_byte >> 2) & 0b111
            b_bits = message_byte & 0b011
            new_r = (r & 0xF8) | r_bits
            new_g = (g & 0xF8) | g_bits
            new_b = (b & 0xFC) | b_bits
        elif mode == "233":
            r_bits = (message_byte >> 6) & 0b011
            g_bits = (message_byte >> 3) & 0b111
            b_bits = message_byte & 0b111
            new_r = (r & 0xFC) | r_bits
            new_g = (g & 0xF8) | g_bits
            new_b = (b & 0xF8) | b_bits
        elif mode == "422":
            r_bits = (message_byte >> 4) & 0b1111
            g_bits = (message_byte >> 2) & 0b011
            b_bits = message_byte & 0b011
            new_r = (r & 0xF0) | r_bits
            new_g = (g & 0xFC) | g_bits
            new_b = (b & 0xFC) | b_bits
        else:
            raise ValueError()
        return new_r, new_g, new_b

    @staticmethod
    def extract_lsb(r: int, g: int, b: int, mode="332") -> int:
        if mode == "332":
            return ((r & 0b111) << 5) | ((g & 0b111) << 2) | (b & 0b011)
        elif mode == "233":
            return ((r & 0b011) << 6) | ((g & 0b111) << 3) | (b & 0b111)
        elif mode == "422":
            return ((r & 0b1111) << 4) | ((g & 0b011) << 2) | (b & 0b011)
        return 0


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
