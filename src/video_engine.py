import cv2
import numpy as np
import matplotlib.pyplot as plt
import math
import struct
import json
import os
import random
import imageio
from crypto_logic import BitManipulator, A51Cipher

class QualityMetrics:
    @staticmethod
    def calculate_mse(cover_frame: np.ndarray, stego_frame: np.ndarray) -> float:
        if cover_frame.shape != stego_frame.shape:
            raise ValueError("Dimensi frame beda, ngga bisa dihitung MSE")
            
        err = np.sum((cover_frame.astype("float") - stego_frame.astype("float")) ** 2)
        err /= float(cover_frame.shape[0] * cover_frame.shape[1] * cover_frame.shape[2])
        return err

    @staticmethod
    def calculate_psnr(cover_frame: np.ndarray, stego_frame: np.ndarray) -> float:
        mse = QualityMetrics.calculate_mse(cover_frame, stego_frame)
        if mse == 0:
            return float('inf')
        
        return 10 * math.log10((255.0 ** 2) / mse)

    @staticmethod
    def generate_histogram(cover_frame: np.ndarray, stego_frame: np.ndarray, save_path: str = None):
        colors = ('b', 'g', 'r')
        plt.figure(figsize=(10, 4))
        
        plt.subplot(1, 2, 1)
        plt.title('Cover Frame RGB Histogram')
        for i, col in enumerate(colors):
            hist = cv2.calcHist([cover_frame], [i], None, [256], [0, 256])
            plt.plot(hist, color=col)
            plt.xlim([0, 256])
            
        plt.subplot(1, 2, 2)
        plt.title('Stego Frame RGB Histogram')
        for i, col in enumerate(colors):
            hist = cv2.calcHist([stego_frame], [i], None, [256], [0, 256])
            plt.plot(hist, color=col)
            plt.xlim([0, 256])
            
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path)
            plt.close()
        else:
            plt.show()

class VideoHandler:
    @staticmethod
    def read_frames(video_path: str):
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise FileNotFoundError("Video ngga kebaca bro!")
            
        fps = cap.get(cv2.CAP_PROP_FPS)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        frames = []
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            frames.append(frame)
            
        cap.release()
        return frames, fps, width, height

    @staticmethod
    def write_avi_lossless(save_path: str, frames: list, fps: float, width: int, height: int):
        fourcc = cv2.VideoWriter_fourcc(*'FFV1')
        out = cv2.VideoWriter(save_path, fourcc, fps, (width, height), isColor=True)
        for frame in frames:
            out.write(frame)
        out.release()
        
    @staticmethod
    def write_mp4_high_quality(save_path: str, frames: list, fps: float, width: int, height: int):
        writer = imageio.get_writer(
            save_path, 
            format='FFMPEG', 
            mode='I', 
            fps=fps, 
            codec='libx264rgb', 
            pixelformat='rgb24', 
            macro_block_size=None,
            ffmpeg_params=['-crf', '0', '-preset', 'ultrafast']
        )
        for frame in frames:
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            writer.append_data(rgb_frame)
        writer.close()
        
class SteganoEngine:
    @staticmethod
    def calculate_capacity(frames: list) -> int:
        if not frames:
            return 0
        h, w, _ = frames[0].shape
        return h * w * len(frames)

    @staticmethod
    def construct_metadata(file_path: str, payload_size: int, is_encrypted: bool, is_random: bool, lsb_mode: str = "332") -> bytes:
        filename = os.path.basename(file_path)
        name, ext = os.path.splitext(filename)
        
        metadata_dict = {
            "magic": "STG26",
            "filename": filename,
            "ext": ext,
            "size": payload_size,
            "encrypted": is_encrypted,
            "random": is_random,
            "lsb_mode": lsb_mode
        }
        
        meta_bytes = json.dumps(metadata_dict).encode('utf-8')
        meta_len_bytes = struct.pack(">I", len(meta_bytes))
        
        return meta_len_bytes + meta_bytes

    @staticmethod
    def _pixel_coordinates(index: int, width: int, height: int):
        frame_idx = index // (width * height)
        rem = index % (width * height)
        y = rem // width
        x = rem % width
        return frame_idx, y, x

    @staticmethod
    def embed_data(frames: list, file_path: str, payload: bytes, is_encrypted: bool, is_random: bool, stego_key: str = None, lsb_mode: str = "332") -> list:
        capacity = SteganoEngine.calculate_capacity(frames)
        meta_bytes = SteganoEngine.construct_metadata(file_path, len(payload), is_encrypted, is_random, lsb_mode)
        
        if len(meta_bytes) + len(payload) > capacity:
            raise ValueError()
            
        h, w, _ = frames[0].shape
        total_pixels = h * w * len(frames)
        
        for i in range(len(meta_bytes)):
            fi, y, x = SteganoEngine._pixel_coordinates(i, w, h)
            b, g, r = frames[fi][y, x]
            new_r, new_g, new_b = BitManipulator.embed_lsb(r, g, b, meta_bytes[i], mode="332")
            frames[fi][y, x] = [new_b, new_g, new_r]
            
        meta_len = len(meta_bytes)
        
        if is_random:
            random.seed(stego_key)
            indices = random.sample(range(meta_len, total_pixels), len(payload))
        else:
            indices = range(meta_len, meta_len + len(payload))
            
        for i, idx in enumerate(indices):
            fi, y, x = SteganoEngine._pixel_coordinates(idx, w, h)
            b, g, r = frames[fi][y, x]
            new_r, new_g, new_b = BitManipulator.embed_lsb(r, g, b, payload[i], mode=lsb_mode)
            frames[fi][y, x] = [new_b, new_g, new_r]
            
        return frames

    @staticmethod
    def extract_data(frames: list, stego_key: str = None) -> tuple:
        h, w, _ = frames[0].shape
        total_pixels = h * w * len(frames)
        
        def get_pixel_byte(index, mode="332"):
            fi, y, x = SteganoEngine._pixel_coordinates(index, w, h)
            b, g, r = frames[fi][y, x]
            return BitManipulator.extract_lsb(r, g, b, mode)
            
        len_bytes = bytearray()
        for i in range(4):
            len_bytes.append(get_pixel_byte(i, "332"))
        meta_len = struct.unpack(">I", bytes(len_bytes))[0]
        
        meta_json_bytes = bytearray()
        for i in range(4, 4 + meta_len):
            meta_json_bytes.append(get_pixel_byte(i, "332"))
            
        try:
            metadata = json.loads(meta_json_bytes.decode('utf-8'))
        except:
            raise ValueError()
        if metadata.get("magic") != "STG26":
            raise ValueError()
            
        payload_size = metadata.get("size")
        is_random = metadata.get("random")
        lsb_mode = metadata.get("lsb_mode", "332")
        total_meta_used = 4 + meta_len
        
        if is_random:
            random.seed(stego_key)
            indices = random.sample(range(total_meta_used, total_pixels), payload_size)
        else:
            indices = range(total_meta_used, total_meta_used + payload_size)
            
        secret_payload = bytearray()
        for idx in indices:
            secret_payload.append(get_pixel_byte(idx, lsb_mode))
            
        return metadata, bytes(secret_payload)
