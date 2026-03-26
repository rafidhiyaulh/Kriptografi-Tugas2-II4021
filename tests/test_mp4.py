import sys
import os
import numpy as np

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.video_engine import SteganoEngine, VideoHandler, QualityMetrics

def test_mp4_lossy():
    print("=== [TESTING BONUS MP4 (H.264)] ===")
    
    plain_text = "INI PESAN UNTUK MEMBUKTIKAN FILE MP4 LOSSY BISA DIEKSTRAK!"
    plain_bytes = plain_text.encode('utf-8')
    print(f"Pesan: '{plain_text}'")
    
    test_file = "test_pesan.txt"
    with open(test_file, 'wb') as f:
        f.write(plain_bytes)
        
    np.random.seed(99)
    dummy_frames = []
    width, height, fps = 100, 100, 30.0
    for _ in range(5):
        frame = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
        dummy_frames.append(frame)
        
    dummy_video_path = "cover_dummy.mp4"
    VideoHandler.write_mp4_high_quality(dummy_video_path, dummy_frames, fps, width, height)
    
    cover_frames, _, _, _ = VideoHandler.read_frames(dummy_video_path)
    
    stego_frames = SteganoEngine.embed_data(
        frames=cover_frames,
        file_path=test_file,
        payload=plain_bytes,
        is_encrypted=False, 
        is_random=False
    )
    
    stego_video_path = "stego_dummy.mp4"
    VideoHandler.write_mp4_high_quality(stego_video_path, stego_frames, fps, width, height)
    print(f"Stego (.mp4) tersimpan: {stego_video_path}")
    
    s_frames, _, _, _ = VideoHandler.read_frames(stego_video_path)
    
    mse = QualityMetrics.calculate_mse(cover_frames[0], s_frames[0])
    psnr = QualityMetrics.calculate_psnr(cover_frames[0], s_frames[0])
    print(f"MSE H.264: {mse:.4f}")
    if psnr != float('inf'):
        print(f"PSNR H.264: {psnr:.2f} dB")
        
    print("\nEkstrak H.264...")
    try:
        extracted_meta, extracted_payload = SteganoEngine.extract_data(s_frames)
        print(f"File terdeteksi: {extracted_meta.get('filename')}")
        
        try:
            print(f"Text yg keluar: '{extracted_payload.decode('utf-8')}'")
        except UnicodeDecodeError:
            print("String ancor gara-gara kompresi mp4.")
            
        if extracted_payload == plain_bytes:
            print("✅ SUCCESS! H.264 + Libx264rgb jaya! Fix Lossless.")
        else:
            print("❌ BIT CORRUPT! Format lossy merusak data LSB.")
    except Exception as e:
        print(f"❌ GAGAL! File corrupt: {str(e)}")

    if os.path.exists(test_file): os.remove(test_file)
    if os.path.exists(dummy_video_path): os.remove(dummy_video_path)
    if os.path.exists(stego_video_path): os.remove(stego_video_path)

if __name__ == '__main__':
    test_mp4_lossy()
