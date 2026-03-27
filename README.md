# SteganoVideo LSB & A5/1

SteganoVideo adalah aplikasi desktop yang dirancang untuk penyisipan dan ekstraksi pesan rahasia (file/teks) ke dalam video berformat `.avi` dan `.mp4`. Aplikasi ini mengimplementasikan teknik LSB (Least Significant Bit) Dinamis yang diperkuat dengan lapisan keamanan Kriptografi Stream Cipher A5/1 dan Pseudo-Random Number Generator (PRNG).

> Laporan Proyek: Rincian lengkap mengenai arsitektur, perhitungan matematis (PSNR/MSE), analisis histogram, serta hasil pengujian dapat diakses pada Laporan Tugas (berada dalam folder `/doc` atau lampiran pengumpulan tugas).

## Tim Pengembang
Tugas 2 II4021 Kriptografi (Semester II Tahun 2025/2026 - Institut Teknologi Bandung)
- Alfandito Rais Akbar (18222037)
- Muhammad Rafi Dhiyaulhaq (18222069)
- Jason Samuel (18223091)

---

## Tech Stack & Dependensi
Aplikasi ini dibangun menggunakan ekosistem Python 3. Seluruh pustaka pendukung dapat dipasang melalui `requirements.txt`:
- `opencv-python` (Manipulasi Matriks Video)
- `numpy` (Komputasi Array Dinamis)
- `matplotlib` (Visualisasi Kurva Histogram)
- `imageio` & `imageio-ffmpeg` (Dukungan Video Lossless MP4)
- `customtkinter` (Antarmuka Graphical User Interface)

---

## Tata Cara Menjalankan Program

Aplikasi dapat dijalankan melalui dua metode:

### 1. Eksekusi Mandiri (.exe) - Windows Only
Bagi pengguna sistem operasi Windows yang tidak memiliki lingkungan Python, silakan klik tautan di bawah untuk mengunduh versi executable. Versi ini tidak memerlukan instalasi pustaka tambahan apa pun.

[Download SteganoVideo .exe](https://drive.google.com/file/d/1sq2zXrylPKb536sFZ2N9u3PBahXPLHwL/view?usp=sharing)

### 2. Eksekusi via Terminal (Semua OS)
Jika Anda ingin menjalankan source code secara langsung melalui Terminal (MacOS/Linux/Windows):
1. Pastikan Python 3 telah terinstal di sistem Anda.
2. Pasang modul yang diperlukan dengan perintah berikut:
   ```bash
   pip install -r requirements.txt
   ```
3. Jalankan program utama untuk membuka antarmuka GUI:
   ```bash
   python main.py
   ```