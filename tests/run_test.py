import sys
import os
import numpy as np
import hashlib

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
from crypto_logic import A51Cipher
from video_engine import SteganoEngine, VideoHandler, QualityMetrics

def test_integration():
    print("=== [TESTING INTEGRASI CORE: RANDOMIZED & ENCRYPTED] ===")
    
    plain_text = "DOKUMEN INI BERADA DI LOKASI PIKSEL ACAK DAN DIENKRIPSI! COBA TEMUKAN SAYA!"
    plain_bytes = plain_text.encode('utf-8')
    key_crypto = "SECRET99"
    key_stego = "SEED_RANDOM_123"
    
    print(f"1. Pesan asli: '{plain_text}'")
    print(f"   Kunci A5/1: {key_crypto} | Stego-Key: {key_stego}")
    
    test_file = "test_pesan.txt"
    with open(test_file, 'wb') as f:
        f.write(plain_bytes)
        
    print("\n2. Generate Video Dummy (AVI)...")
    np.random.seed(42)
    dummy_frames = []
    width, height, fps = 100, 100, 30.0
    for _ in range(5):
        frame = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
        dummy_frames.append(frame)
        
    dummy_video_path = "cover_dummy.avi"
    VideoHandler.write_avi_lossless(dummy_video_path, dummy_frames, fps, width, height)
    
    print("\n3. Enkripsi A5/1 jalan...")
    cipher = A51Cipher(key_crypto)
    encrypted_bytes = cipher.process(plain_bytes)
    
    print("\n4. Embedding LSB acak...")
    cover_frames, _, _, _ = VideoHandler.read_frames(dummy_video_path)
    
    stego_frames = SteganoEngine.embed_data(
        frames=cover_frames,
        file_path=test_file,
        payload=encrypted_bytes,
        is_encrypted=True,
        is_random=True,
        stego_key=key_stego
    )
    
    stego_video_path = "stego_dummy_random.avi"
    VideoHandler.write_avi_lossless(stego_video_path, stego_frames, fps, width, height)
    print(f"   Saved ke: {stego_video_path}")
    
    print("\n5. Hitung Metrik Kualitas...")
    c_frames, _, _, _ = VideoHandler.read_frames(dummy_video_path)
    s_frames, _, _, _ = VideoHandler.read_frames(stego_video_path)
    
    mse = QualityMetrics.calculate_mse(c_frames[0], s_frames[0])
    psnr = QualityMetrics.calculate_psnr(c_frames[0], s_frames[0])
    print(f"   MSE Frame-0 : {mse:.4f}")
    if psnr != float('inf'):
        print(f"   PSNR Frame-0: {psnr:.2f} dB")
    
    print("\n6. Ekstraksi...")
    extracted_meta, extracted_cipher = SteganoEngine.extract_data(s_frames, stego_key=key_stego)
    
    print(f"   [Header ketemu]: File={extracted_meta['filename']}, Random={extracted_meta['random']}, Enkripsi={extracted_meta['encrypted']}")
    
    print("\n7. Dekripsi pesan...")
    extract_cipher = A51Cipher(key_crypto)
    decrypted_bytes = extract_cipher.process(extracted_cipher)
    decrypted_text = decrypted_bytes.decode('utf-8')
    
    print(f"\n   [HASIL EKSTRAK] -> '{decrypted_text}'")
    
    if plain_bytes == decrypted_bytes:
        print("\n✅ SUCCESS! Semuanya works.")
    else:
        print("\n❌ GAGAL! Ada bug saat proses.")

    if os.path.exists(test_file): os.remove(test_file)
    if os.path.exists(dummy_video_path): os.remove(dummy_video_path)
    if os.path.exists(stego_video_path): os.remove(stego_video_path)

if __name__ == '__main__':
    test_integration()
