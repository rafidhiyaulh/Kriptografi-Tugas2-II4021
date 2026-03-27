import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import hashlib

from src.video_engine import SteganoEngine, VideoHandler, QualityMetrics
from src.crypto_logic import A51Cipher


class SectionFrame(ctk.CTkFrame):
    def __init__(self, parent, title, **kwargs):
        super().__init__(parent, corner_radius=10, fg_color=("gray90", "gray17"), **kwargs)
        self.columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self, text=title,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("gray40", "gray60"),
            anchor="w"
        ).grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 4))


class SteganoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SteganoVideo")
        self.geometry("860x740")
        self.minsize(780, 640)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.tabview = ctk.CTkTabview(self, corner_radius=12)
        self.tabview.pack(padx=24, pady=(16, 20), fill="both", expand=True)
        self.tabview.add("Embedding")
        self.tabview.add("Extraction")
        self.tabview.add("Verifikasi MD5")

        self.setup_embedding_tab()
        self.setup_extraction_tab()
        self.setup_md5_tab()

    def setup_embedding_tab(self):
        tab = self.tabview.tab("Embedding")
        tab.columnconfigure(0, weight=1)

        row = 0

        sec_video = SectionFrame(tab, "COVER VIDEO")
        sec_video.grid(row=row, column=0, sticky="ew", padx=4, pady=(4, 6))
        sec_video.columnconfigure(1, weight=1)

        ctk.CTkLabel(sec_video, text="File Video (AVI / MP4)", anchor="w").grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 10))
        self.entry_video = ctk.CTkEntry(sec_video, placeholder_text="Pilih file video…")
        self.entry_video.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(0, 10))
        ctk.CTkButton(sec_video, text="Browse", width=80,
                      command=self.browse_video).grid(row=1, column=2, padx=(0, 14), pady=(0, 10))

        row += 1

        sec_msg = SectionFrame(tab, "PAYLOAD")
        sec_msg.grid(row=row, column=0, sticky="ew", padx=4, pady=6)
        sec_msg.columnconfigure(1, weight=1)

        radio_frame = ctk.CTkFrame(sec_msg, fg_color="transparent")
        radio_frame.grid(row=1, column=0, columnspan=3, sticky="w", padx=14, pady=(0, 6))
        ctk.CTkLabel(radio_frame, text="Tipe Pesan:", anchor="w").pack(side="left", padx=(0, 12))
        self.msg_type_var = ctk.StringVar(value="file")
        ctk.CTkRadioButton(radio_frame, text="File", variable=self.msg_type_var,
                           value="file", command=self.toggle_input_mode).pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(radio_frame, text="Teks", variable=self.msg_type_var,
                           value="text", command=self.toggle_input_mode).pack(side="left")

        self.label_payload = ctk.CTkLabel(sec_msg, text="Pilih File:", anchor="w", width=90)
        self.label_payload.grid(row=2, column=0, sticky="w", padx=14, pady=(0, 10))
        self.entry_payload = ctk.CTkEntry(sec_msg, placeholder_text="Pilih file pesan atau ketik teks…")
        self.entry_payload.grid(row=2, column=1, sticky="ew", padx=(0, 8), pady=(0, 10))
        self.btn_browse_payload = ctk.CTkButton(sec_msg, text="Browse", width=80,
                                                command=self.browse_payload)
        self.btn_browse_payload.grid(row=2, column=2, padx=(0, 14), pady=(0, 10))

        self.label_info_cap = ctk.CTkLabel(
            sec_msg, text="Kapasitas: —  |  Ukuran Pesan: —",
            font=ctk.CTkFont(size=11), text_color="gray", anchor="w")
        self.label_info_cap.grid(row=3, column=0, columnspan=3, sticky="w", padx=14, pady=(0, 10))

        row += 1

        sec_cfg = SectionFrame(tab, "KONFIGURASI ENKRIPSI & PENYISIPAN")
        sec_cfg.grid(row=row, column=0, sticky="ew", padx=4, pady=6)
        sec_cfg.columnconfigure(1, weight=1)

        self.check_encrypt = ctk.CTkCheckBox(sec_cfg, text="Gunakan Enkripsi A5/1 (Wajib 8 Karakter)",
                                             command=self._toggle_encrypt_key)
        self.check_encrypt.grid(row=1, column=0, columnspan=2, sticky="w", padx=14, pady=(0, 4))

        self.entry_key_a51 = ctk.CTkEntry(sec_cfg, placeholder_text="Kunci A5/1 (8 karakter)",
                                          state="disabled")
        self.entry_key_a51.grid(row=2, column=0, columnspan=3, sticky="ew", padx=14, pady=(0, 10))

        ctk.CTkFrame(sec_cfg, height=1, fg_color=("gray75", "gray30")).grid(
            row=3, column=0, columnspan=3, sticky="ew", padx=14, pady=4)

        self.check_random = ctk.CTkCheckBox(sec_cfg, text="Penyisipan Acak (Randomized)",
                                            command=self._toggle_stego_key)
        self.check_random.grid(row=4, column=0, columnspan=2, sticky="w", padx=14, pady=(8, 4))

        self.entry_stego_key = ctk.CTkEntry(sec_cfg, placeholder_text="Stego Key / Seed",
                                            state="disabled")
        self.entry_stego_key.grid(row=5, column=0, columnspan=3, sticky="ew", padx=14, pady=(0, 14))

        row += 1

        sec_lsb = SectionFrame(tab, "ALOKASI BIT LSB  (Total harus = 8)")
        sec_lsb.grid(row=row, column=0, sticky="ew", padx=4, pady=6)

        lsb_inner = ctk.CTkFrame(sec_lsb, fg_color="transparent")
        lsb_inner.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 12))

        for i, (channel, default, attr) in enumerate([
            ("Red (R)", "3", "entry_r_bits"),
            ("Green (G)", "3", "entry_g_bits"),
            ("Blue (B)", "2", "entry_b_bits"),
        ]):
            ctk.CTkLabel(lsb_inner, text=channel, anchor="w", width=80).grid(
                row=0, column=i * 2, padx=(0 if i == 0 else 16, 4))
            entry = ctk.CTkEntry(lsb_inner, width=64, justify="center")
            entry.insert(0, default)
            entry.grid(row=0, column=i * 2 + 1, padx=(0, 4))
            setattr(self, attr, entry)

        row += 1

        self.btn_embed = ctk.CTkButton(
            tab, text="▶  Mulai Embedding", height=44,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#1a7a3c", hover_color="#155e2e",
            corner_radius=10, command=self.run_embedding)
        self.btn_embed.grid(row=row, column=0, sticky="ew", padx=4, pady=(12, 4))

        self._video_trace_var = ctk.StringVar()
        self._video_trace_var.trace_add("write", lambda *_: self.update_capacity_info())
        self.entry_video._entry.config(textvariable=self._video_trace_var)

        self._payload_trace_var = ctk.StringVar()
        self._payload_trace_var.trace_add("write", lambda *_: self.update_capacity_info())
        self.entry_payload._entry.config(textvariable=self._payload_trace_var)

    def setup_extraction_tab(self):
        tab = self.tabview.tab("Extraction")
        tab.columnconfigure(0, weight=1)

        row = 0

        sec_src = SectionFrame(tab, "STEGO VIDEO")
        sec_src.grid(row=row, column=0, sticky="ew", padx=4, pady=(4, 6))
        sec_src.columnconfigure(1, weight=1)

        ctk.CTkLabel(sec_src, text="File Video (AVI)", anchor="w").grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 10))
        self.entry_stego_input = ctk.CTkEntry(sec_src, placeholder_text="Pilih stego video…")
        self.entry_stego_input.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(0, 10))
        ctk.CTkButton(sec_src, text="Browse", width=80,
                      command=lambda: self.browse_generic(self.entry_stego_input)).grid(
            row=1, column=2, padx=(0, 14), pady=(0, 10))

        row += 1

        sec_keys = SectionFrame(tab, "KUNCI")
        sec_keys.grid(row=row, column=0, sticky="ew", padx=4, pady=6)
        sec_keys.columnconfigure(1, weight=1)

        ctk.CTkLabel(sec_keys, text="Kunci A5/1", anchor="w", width=110).grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 6))
        self.entry_ext_key_a51 = ctk.CTkEntry(sec_keys,
                                               placeholder_text="Kosongkan jika tidak terenkripsi",
                                               show="●")
        self.entry_ext_key_a51.grid(row=1, column=1, sticky="ew", padx=(0, 14), pady=(0, 6))

        ctk.CTkLabel(sec_keys, text="Stego Key", anchor="w", width=110).grid(
            row=2, column=0, sticky="w", padx=14, pady=(0, 10))
        self.entry_ext_stego_key = ctk.CTkEntry(sec_keys,
                                                 placeholder_text="Kosongkan jika sekuensial")
        self.entry_ext_stego_key.grid(row=2, column=1, sticky="ew", padx=(0, 14), pady=(0, 10))

        row += 1

        self.btn_extract = ctk.CTkButton(
            tab, text="▶  Mulai Ekstraksi", height=44,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#1a7a3c", hover_color="#155e2e",
            corner_radius=10, command=self.run_extraction)
        self.btn_extract.grid(row=row, column=0, sticky="ew", padx=4, pady=(12, 4))

    def setup_md5_tab(self):
        tab = self.tabview.tab("Verifikasi MD5")
        tab.columnconfigure(0, weight=1)

        row = 0

        sec_md5 = SectionFrame(tab, "UJI INTEGRITAS BERKAS (MD5 Hash)")
        sec_md5.grid(row=row, column=0, sticky="ew", padx=4, pady=(4, 6))
        sec_md5.columnconfigure(1, weight=1)

        ctk.CTkLabel(sec_md5, text="Berkas Asli", anchor="w").grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 10))
        self.entry_md5_1 = ctk.CTkEntry(sec_md5, placeholder_text="Pilih berkas rahasia sebelum embedding…")
        self.entry_md5_1.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(0, 10))
        ctk.CTkButton(sec_md5, text="Browse", width=80,
                      command=lambda: self.browse_generic(self.entry_md5_1)).grid(
            row=1, column=2, padx=(0, 14), pady=(0, 10))

        ctk.CTkLabel(sec_md5, text="Berkas Ekstraksi", anchor="w").grid(
            row=2, column=0, sticky="w", padx=14, pady=(0, 10))
        self.entry_md5_2 = ctk.CTkEntry(sec_md5, placeholder_text="Pilih berkas rahasia hasil ekstraksi…")
        self.entry_md5_2.grid(row=2, column=1, sticky="ew", padx=(0, 8), pady=(0, 10))
        ctk.CTkButton(sec_md5, text="Browse", width=80,
                      command=lambda: self.browse_generic(self.entry_md5_2)).grid(
            row=2, column=2, padx=(0, 14), pady=(0, 10))

        row += 1

        self.btn_check_md5 = ctk.CTkButton(
            tab, text="✔ Hitung & Bandingkan MD5", height=44,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#1a7a3c", hover_color="#155e2e",
            corner_radius=10, command=self.run_md5_check)
        self.btn_check_md5.grid(row=row, column=0, sticky="ew", padx=4, pady=(12, 4))
        
        self.label_md5_result = ctk.CTkLabel(tab, text="Silakan pilih 2 file untuk menguji kecocokan 100% bit.", font=ctk.CTkFont(size=13))
        self.label_md5_result.grid(row=row+1, column=0, pady=20)

    def _toggle_encrypt_key(self):
        state = "normal" if self.check_encrypt.get() else "disabled"
        self.entry_key_a51.configure(state=state)

    def _toggle_stego_key(self):
        state = "normal" if self.check_random.get() else "disabled"
        self.entry_stego_key.configure(state=state)

    def browse_video(self):
        path = filedialog.askopenfilename(filetypes=[("Video files", "*.avi *.mp4")])
        if not path:
            return
        self.entry_video.delete(0, 'end')
        self.entry_video.insert(0, path)
        self.input_extension = os.path.splitext(path)[1].lower()

    def browse_payload(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self.entry_payload.delete(0, 'end')
        self.entry_payload.insert(0, path)

    def browse_generic(self, entry_widget):
        path = filedialog.askopenfilename()
        if not path:
            return
        entry_widget.delete(0, 'end')
        entry_widget.insert(0, path)

    def toggle_input_mode(self):
        if self.msg_type_var.get() == "text":
            self.label_payload.configure(text="Input Teks:")
            self.btn_browse_payload.configure(state="disabled")
        else:
            self.label_payload.configure(text="Pilih File:")
            self.btn_browse_payload.configure(state="normal")
        self.update_capacity_info()

    def update_capacity_info(self):
        try:
            video_path = self.entry_video.get()
            if not video_path:
                return

            frames, _, _, _ = VideoHandler.read_frames(video_path)
            capacity = SteganoEngine.calculate_capacity(frames)

            if self.msg_type_var.get() == "text":
                payload_size = len(self.entry_payload.get().encode('utf-8'))
            else:
                payload_path = self.entry_payload.get()
                payload_size = os.path.getsize(payload_path) if os.path.exists(payload_path) else 0

            color = "green" if payload_size <= capacity else "red"
            self.label_info_cap.configure(
                text=f"Kapasitas: {capacity} bytes  |  Ukuran Pesan: {payload_size} bytes",
                text_color=color
            )
            return capacity, payload_size
        except Exception:
            pass

    def _bind_update(self, entry: ctk.CTkEntry):
        inner = entry._entry 
        inner.bind("<KeyRelease>", lambda *_: self.update_capacity_info())
        inner_var = entry._entry["textvariable"] if entry._entry["textvariable"] else None
        if inner_var:
            self.tk.globalsetvar(inner_var, "")
        var = ctk.StringVar()
        entry._entry.config(textvariable=var)
        var.trace_add("write", lambda *_: self.update_capacity_info())
        return var
    

    def run_embedding(self):
        video_path = self.entry_video.get()
        is_encrypted = self.check_encrypt.get()
        is_random = self.check_random.get()

        try:
            r_bits = int(self.entry_r_bits.get())
            g_bits = int(self.entry_g_bits.get())
            b_bits = int(self.entry_b_bits.get())
            if r_bits + g_bits + b_bits != 8:
                raise ValueError("Total bits R+G+B must be 8")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid LSB bits: {e}")
            return

        try:
            if self.msg_type_var.get() == "text":
                raw_text = self.entry_payload.get()
                if not raw_text:
                    raise ValueError("Pesan teks tidak boleh kosong")
                data = raw_text.encode('utf-8')
                payload_path = "pesan_teks.txt"
            else:
                payload_path = self.entry_payload.get()
                if not os.path.exists(payload_path):
                    raise ValueError("File pesan tidak ditemukan")
                with open(payload_path, 'rb') as f:
                    data = f.read()

            if not video_path:
                raise ValueError("Pilih video cover terlebih dahulu")

            frames, fps, w, h = VideoHandler.read_frames(video_path)
            original_frame = [f.copy() for f in frames]

            capacity = SteganoEngine.calculate_capacity(frames)

            if len(data) + 500 > capacity:
                raise ValueError(
                    f"Ukuran pesan ({len(data)} bytes) melebihi kapasitas sisip ({capacity} bytes)!")

            if is_encrypted:
                key_a51 = self.entry_key_a51.get()
                if not key_a51:
                    raise ValueError("Kunci A5/1 diperlukan untuk enkripsi")
                cipher = A51Cipher(key_a51)
                data = cipher.process(data)

            stego_frames = SteganoEngine.embed_data(
                frames, payload_path, data, is_encrypted, is_random,
                self.entry_stego_key.get(), r_bits, g_bits, b_bits
            )

            if not hasattr(self, 'input_extension'):
                self.input_extension = os.path.splitext(video_path)[1].lower()

            save_path = filedialog.asksaveasfilename(
                defaultextension=self.input_extension,
                filetypes=[("Original Format", f"*{self.input_extension}"),
                           ("AVI Video", "*.avi"), ("MP4 Video", "*.mp4")]
            )

            if not save_path:
                return

            if save_path.lower().endswith(".mp4"):
                VideoHandler.write_mp4_high_quality(save_path, stego_frames, fps, w, h)
            else:
                VideoHandler.write_avi_lossless(save_path, stego_frames, fps, w, h)

            mse = QualityMetrics.calculate_mse(original_frame[0], stego_frames[0])
            psnr = QualityMetrics.calculate_psnr(original_frame[0], stego_frames[0])
            
            messagebox.showinfo("Sukses", f"Stego-video berhasil disimpan!\nMSE: {mse:.4f}\nPSNR: {psnr:.2f} dB")

            QualityMetrics.generate_histogram(original_frame[0], stego_frames[0])

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_extraction(self):
        try:
            stego_path = self.entry_stego_input.get()
            a51_key = self.entry_ext_key_a51.get()
            stego_key = self.entry_ext_stego_key.get()

            frames, _, _, _ = VideoHandler.read_frames(stego_path)
            metadata, payload = SteganoEngine.extract_data(frames, stego_key)

            if metadata.get("encrypted"):
                if not a51_key:
                    raise ValueError("A5/1 key required for encrypted data")
                cipher = A51Cipher(a51_key)
                payload = cipher.process(payload)

            save_path = filedialog.asksaveasfilename(
                initialfile=metadata.get("filename"),
                defaultextension=metadata.get("ext")
            )
            with open(save_path, 'wb') as f:
                f.write(payload)

            messagebox.showinfo("Sukses", f"Berhasil ekstrak: {metadata.get('filename')}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_md5_check(self):
        file1 = self.entry_md5_1.get()
        file2 = self.entry_md5_2.get()
        
        if not os.path.exists(file1) or not os.path.exists(file2):
            messagebox.showerror("Error", "Pastikan kedua file telah dipilih dan ada di komputer Anda.")
            return
            
        try:
            with open(file1, 'rb') as f1:
                hash1 = hashlib.md5(f1.read()).hexdigest()
            with open(file2, 'rb') as f2:
                hash2 = hashlib.md5(f2.read()).hexdigest()
                
            if hash1 == hash2:
                color = "#20a149"
                msg = f"INTEGRITAS TERJAGA SEMPURNA (100% MATCH)\n\nHash Berkas Asli:\n{hash1}\n\nHash Berkas Ekstraksi:\n{hash2}"
            else:
                color = "#d93b3b"
                msg = f"BERKAS CORRUPT BEDA ISINYA\n\nHash Asli:\n{hash1}\n\nHash Ekstraksi:\n{hash2}"
                
            self.label_md5_result.configure(text=msg, text_color=color)
        except Exception as e:
            messagebox.showerror("MD5 Error", f"Gagal menghitung MD5: {str(e)}")