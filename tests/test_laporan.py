import sys
import os
import numpy as np
import hashlib
import glob

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
from src.crypto_logic import A51Cipher
from src.video_engine import SteganoEngine, VideoHandler, QualityMetrics

def test_kombinasi_dan_kapasitas():
    print("=== [PENGUJIAN KOMBINASI & KAPASITAS (BUKTI LAPORAN)] ===\n")
    
    width, height, fps = 10, 10, 30.0
    frames = [np.random.randint(0, 256, (height, width, 3), dtype=np.uint8) for _ in range(3)]
    dummy_video_path = "cover_mini.avi"
    VideoHandler.write_avi_lossless(dummy_video_path, frames, fps, width, height)
    
    print("--- [1] TEST: KAPASITAS BERLEBIH ---")
    cover_frames, _, _, _ = VideoHandler.read_frames(dummy_video_path)
    big_payload = os.urandom(5000)
    try:
        SteganoEngine.embed_data(cover_frames, "tes.txt", big_payload, False, False)
        print("X GAGAL: Seharusnya melemparkan exception kapasitas.")
    except ValueError:
        print("V SUKSES: Sistem menolak payload yang melebihi kapasitas.")
        
    print("\n--- [2] TEST: KOMBINASI KONFIGURASI, PSNR & INTEGRITAS ---")
    lsb_modes = ["332", "233", "422"]
    embed_modes = [False, True]
    crypto_modes = [False, True]
    
    key_crypto = "Secret99"
    key_stego = "RandomKey123"
    txt_payload = b"Ini adalah pesan standar untuk kombinasi 12 iterasi."
    
    for l_mode in lsb_modes:
        for rng_mode in embed_modes:
            for cryp_mode in crypto_modes:
                test_name = f"Mode={l_mode} | Rand={rng_mode} | Crypt={cryp_mode}"
                
                c_frames = [f.copy() for f in frames]
                
                payload = txt_payload
                if cryp_mode:
                    cipher = A51Cipher(key_crypto)
                    payload = cipher.process(payload)
                    
                stego_frames = SteganoEngine.embed_data(
                    c_frames, "tes.txt", payload, cryp_mode, rng_mode, key_stego, l_mode
                )
                
                mse = QualityMetrics.calculate_mse(frames[0], stego_frames[0])
                psnr = QualityMetrics.calculate_psnr(frames[0], stego_frames[0])
                
                meta, ext_payload = SteganoEngine.extract_data(stego_frames, key_stego)
                if cryp_mode:
                    decipher = A51Cipher(key_crypto)
                    ext_payload = decipher.process(ext_payload)
                    
                hash_in = hashlib.md5(txt_payload).hexdigest()
                hash_out = hashlib.md5(ext_payload).hexdigest()
                
                print(f"[{test_name}]")
                print(f"   => PSNR: {psnr:.2f} dB, MSE: {mse:.4f}")
                print(f"   => MD5 Murni: {hash_in == hash_out}")
                
                if l_mode == "422" and cryp_mode and rng_mode:
                    QualityMetrics.generate_histogram(frames[0], stego_frames[0], "hist_422.png")
                    print("   => Histogram disimpan ke hist_422.png")

    print("\n--- [3] TEST: BERBAGAI JENIS FILE (.txt, .pdf, .png, .jpg, .docx, .exe) ---")
    
    width, height, fps = 100, 100, 30.0
    big_frames = [np.random.randint(0, 256, (height, width, 3), dtype=np.uint8) for _ in range(10)]
    
    file_list = glob.glob(os.path.join(os.path.dirname(__file__), '../berkas_uji/pesan_*'))
    for filepath in file_list:
        with open(filepath, 'rb') as f:
            raw_data = f.read()
            
        c_frames = [f.copy() for f in big_frames]
        stego_frames = SteganoEngine.embed_data(c_frames, filepath, raw_data, False, False, lsb_mode="332")
        meta, ext_data = SteganoEngine.extract_data(stego_frames)
        
        hash_in = hashlib.md5(raw_data).hexdigest()
        hash_out = hashlib.md5(ext_data).hexdigest()
        ext = os.path.splitext(filepath)[1]
        print(f"Uji Ekstensi '{ext}': MD5 Match = {hash_in == hash_out}")

    if os.path.exists(dummy_video_path): os.remove(dummy_video_path)

if __name__ == '__main__':
    test_kombinasi_dan_kapasitas()
