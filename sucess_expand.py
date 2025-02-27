import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from PIL import Image, ImageTk

# ==============================================
# Manual AES-256 Simulation
# ==============================================
class AES256:
    def __init__(self):
        self.rounds = 14  # AES-256 uses 14 rounds
        self.key_size = 32  # 256 bits = 32 bytes

    def _sub_bytes(self, state):
        """ Substitution step (S-box substitution) """
        sbox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]
        return bytes(sbox[b] for b in state)
    
    def _rot_word(self, word):
        word_bytes = word.to_bytes(4, 'big')  # Convert the word to 4 bytes
        rotated = word_bytes[1:] + word_bytes[:1]  # Rotate left by 1 byte
        return int.from_bytes(rotated, 'big')  # Convert back to an integer

    def _inv_sub_bytes(self, state):
        """ Inverse substitution step (inverse S-box substitution) """
        inv_sbox = [
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        ]
        return bytes(inv_sbox[b] for b in state)

    def _shift_rows(self, state):
        """ Shift rows transformation """
        shifted = bytearray(state)
        shifted[1], shifted[5], shifted[9], shifted[13] = state[5], state[9], state[13], state[1]
        shifted[2], shifted[6], shifted[10], shifted[14] = state[10], state[14], state[2], state[6]
        shifted[3], shifted[7], shifted[11], shifted[15] = state[15], state[3], state[7], state[11]
        return bytes(shifted)

    def _inv_shift_rows(self, state):
        """ Inverse shift rows transformation """
        shifted = bytearray(state)
        shifted[1], shifted[5], shifted[9], shifted[13] = state[13], state[1], state[5], state[9]
        shifted[2], shifted[6], shifted[10], shifted[14] = state[10], state[14], state[2], state[6]
        shifted[3], shifted[7], shifted[11], shifted[15] = state[7], state[11], state[15], state[3]
        return bytes(shifted)

    def _mix_columns(self, state):
        """ Mix columns transformation """
        mix_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]
        mixed = bytearray(16)
        for i in range(4):
            for j in range(4):
                mixed[i * 4 + j] = (
                    self._gmul(mix_matrix[i][0], state[j * 4 + 0]) ^
                    self._gmul(mix_matrix[i][1], state[j * 4 + 1]) ^
                    self._gmul(mix_matrix[i][2], state[j * 4 + 2]) ^
                    self._gmul(mix_matrix[i][3], state[j * 4 + 3])
                )
        return bytes(mixed)

    def _inv_mix_columns(self, state):
        """ Inverse mix columns transformation """
        inv_mix_matrix = [
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ]
        mixed = bytearray(16)
        for i in range(4):
            for j in range(4):
                mixed[i * 4 + j] = (
                    self._gmul(inv_mix_matrix[i][0], state[j * 4 + 0]) ^
                    self._gmul(inv_mix_matrix[i][1], state[j * 4 + 1]) ^
                    self._gmul(inv_mix_matrix[i][2], state[j * 4 + 2]) ^
                    self._gmul(inv_mix_matrix[i][3], state[j * 4 + 3])
                )
        return bytes(mixed)

    def _gmul(self, a, b):
        """ Galois field multiplication """
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # XOR with irreducible polynomial
            b >>= 1
        return p & 0xFF

    def _add_round_key(self, state, round_key):
        """ XOR state with round key """
        for i in range(len(state)):
            state[i] ^= round_key[i]

    def _key_expansion(self, key):
        """ Key expansion for AES-256 """
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        expanded_key = bytearray(key)  # Start with the original key (32 bytes)
        for i in range(32, 240):  # Expand to 240 bytes (15 rounds * 16 bytes per round)
            temp = int.from_bytes(expanded_key[i - 4:i], 'big')
            if i % 32 == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ rcon[i // 32 - 1]
            elif i % 32 == 16:
                temp = self._sub_word(temp)
            temp ^= int.from_bytes(expanded_key[i - 32:i - 28], 'big')
            expanded_key.extend(temp.to_bytes(4, 'big'))
        return expanded_key

    def _sub_word(self, word):
        """ Substitute word using S-box """
        sbox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]
        # Convert the 32-bit word into bytes
        word_bytes = word.to_bytes(4, 'big')
        # Substitute each byte using the S-box
        substituted = bytes(sbox[b] for b in word_bytes)
        # Convert the substituted bytes back into a 32-bit integer
        return int.from_bytes(substituted, 'big')
    def _inv_mix_columns(self, state):
        """ Inverse mix columns transformation """
        inv_mix_matrix = [
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ]
        mixed = bytearray(16)
        for i in range(4):
            for j in range(4):
                mixed[i * 4 + j] = (
                    self._gmul(inv_mix_matrix[i][0], state[j * 4 + 0]) ^
                    self._gmul(inv_mix_matrix[i][1], state[j * 4 + 1]) ^
                    self._gmul(inv_mix_matrix[i][2], state[j * 4 + 2]) ^
                    self._gmul(inv_mix_matrix[i][3], state[j * 4 + 3])
                )
        return bytes(mixed)

    def encrypt(self, plaintext, key):
        """ Encrypt using AES-256 """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256 encryption")
        
        # Ensure plaintext is exactly 16 bytes (AES block size)
        if len(plaintext) < 16:
            plaintext = plaintext.ljust(16, b"\x00")  # Pad with null bytes
        elif len(plaintext) > 16:
            raise ValueError("Plaintext must be exactly 16 bytes for AES encryption")
        
        # Key expansion
        key_schedule = self._key_expansion(bytearray(key))
        
        # Initialize the state
        state = bytearray(plaintext)
        
        # Initial round: Add round key
        self._add_round_key(state, key_schedule[:16])
        
        # Main rounds
        for round_num in range(1, self.rounds):
            state = bytearray(self._sub_bytes(state))
            state = bytearray(self._shift_rows(state))
            if round_num < self.rounds - 1:  # Skip MixColumns in the last round
                state = bytearray(self._mix_columns(state))
            self._add_round_key(state, key_schedule[round_num * 16:(round_num + 1) * 16])
        
        return bytes(state)

    def decrypt(self, ciphertext, key):
        """ Decrypt using AES-256 """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256 decryption")
        
        # Ensure ciphertext is exactly 16 bytes (AES block size)
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext must be at least 16 bytes for AES decryption")
        ciphertext = ciphertext[:16]  # Truncate to 16 bytes if longer
        
        # Key expansion
        key_schedule = self._key_expansion(bytearray(key))
        
        # Initialize the state
        state = bytearray(ciphertext)
        
        # Final round: Add round key
        self._add_round_key(state, key_schedule[-16:])
        
        # Reverse rounds
        for round_num in range(self.rounds - 1, 0, -1):
            state = bytearray(self._inv_shift_rows(state))
            state = bytearray(self._inv_sub_bytes(state))
            self._add_round_key(state, key_schedule[round_num * 16:(round_num + 1) * 16])
            if round_num > 1:  # Skip InvMixColumns in the first round
                state = bytearray(self._inv_mix_columns(state))
        
        # Initial round: Inverse transformations
        state = bytearray(self._inv_shift_rows(state))
        state = bytearray(self._inv_sub_bytes(state))
        self._add_round_key(state, key_schedule[:16])
        
        return bytes(state)
        
# ==============================================
# Manual ChaCha20 Simulation
# ==============================================
import struct

class ChaCha20:
    def __init__(self, key, nonce, counter=0):
        """
        Initialize the ChaCha20 cipher with a key, nonce, and counter.
        - Key: 32 bytes (256 bits)
        - Nonce: 12 bytes
        - Counter: 32-bit integer
        """
        self.constants = b'expand 32-byte k'  # Fixed ChaCha20 constants
        self.key = key.ljust(32, b'\0')[:32]  # Ensure key is exactly 32 bytes
        self.nonce = nonce.ljust(12, b'\0')[:12]  # Ensure nonce is exactly 12 bytes
        self.counter = counter  # 32-bit counter

    def _quarter_round(self, a, b, c, d):
        """
        Perform a single ChaCha20 quarter-round operation.
        """
        a = (a + b) & 0xFFFFFFFF
        d = (d ^ a) & 0xFFFFFFFF
        d = ((d << 16) | (d >> 16)) & 0xFFFFFFFF  # Rotate left by 16 bits
        c = (c + d) & 0xFFFFFFFF
        b = (b ^ c) & 0xFFFFFFFF
        b = ((b << 12) | (b >> 20)) & 0xFFFFFFFF  # Rotate left by 12 bits
        a = (a + b) & 0xFFFFFFFF
        d = (d ^ a) & 0xFFFFFFFF
        d = ((d << 8) | (d >> 24)) & 0xFFFFFFFF  # Rotate left by 8 bits
        c = (c + d) & 0xFFFFFFFF
        b = (b ^ c) & 0xFFFFFFFF
        b = ((b << 7) | (b >> 25)) & 0xFFFFFFFF  # Rotate left by 7 bits
        return a, b, c, d

    def _chacha_block(self):
        """
        Generate one block of ChaCha20 keystream (64 bytes).
        """
        # Initialize the ChaCha20 state
        state = list(struct.unpack('<16I', self.constants + self.key + self.counter.to_bytes(4, 'little') + self.nonce))
        working_state = state[:]  # Copy the initial state for modification

        # Perform 20 rounds (10 column rounds + 10 diagonal rounds)
        for _ in range(10):
            # Column rounds
            working_state[0], working_state[4], working_state[8], working_state[12] = self._quarter_round(
                working_state[0], working_state[4], working_state[8], working_state[12]
            )
            working_state[1], working_state[5], working_state[9], working_state[13] = self._quarter_round(
                working_state[1], working_state[5], working_state[9], working_state[13]
            )
            working_state[2], working_state[6], working_state[10], working_state[14] = self._quarter_round(
                working_state[2], working_state[6], working_state[10], working_state[14]
            )
            working_state[3], working_state[7], working_state[11], working_state[15] = self._quarter_round(
                working_state[3], working_state[7], working_state[11], working_state[15]
            )

            # Diagonal rounds
            working_state[0], working_state[5], working_state[10], working_state[15] = self._quarter_round(
                working_state[0], working_state[5], working_state[10], working_state[15]
            )
            working_state[1], working_state[6], working_state[11], working_state[12] = self._quarter_round(
                working_state[1], working_state[6], working_state[11], working_state[12]
            )
            working_state[2], working_state[7], working_state[8], working_state[13] = self._quarter_round(
                working_state[2], working_state[7], working_state[8], working_state[13]
            )
            working_state[3], working_state[4], working_state[9], working_state[14] = self._quarter_round(
                working_state[3], working_state[4], working_state[9], working_state[14]
            )

        # Add the initial state to the working state
        final_state = [(s + w) & 0xFFFFFFFF for s, w in zip(state, working_state)]

        # Pack the final state into a 64-byte block
        return struct.pack('<16I', *final_state)

    def encrypt(self, plaintext):
        """
        Encrypt plaintext using ChaCha20.
        """
        encrypted = bytearray()
        for i in range(0, len(plaintext), 64):
            block = self._chacha_block()  # Generate a new keystream block
            for j in range(min(64, len(plaintext) - i)):
                encrypted.append(plaintext[i + j] ^ block[j])  # XOR plaintext with keystream
            self.counter += 1  # Increment the counter for the next block
        return bytes(encrypted)

    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext using ChaCha20.
        """
        return self.encrypt(ciphertext)  # Encryption and decryption are identical
# ==============================================
# Password Hashing (Simulated KDF)
# ==============================================
def simple_password_hash(password):
    """ Create a 32-byte key from password """
    hash_result = 0
    for char in password:
        hash_result = (hash_result * 31 + ord(char)) % (2**32)
    # Extend to 32 bytes by repeating the 4-byte hash
    hash_bytes = hash_result.to_bytes(4, 'big') * 8
    return hash_bytes

# ==============================================
# LSB Steganography: Hide & Reveal Data
# ==============================================
def hide_data(image_path, data):
    img = Image.open(image_path).convert('RGB')
    data_length = len(data)
    length_indicator = data_length.to_bytes(4, byteorder='big')
    data_with_length = length_indicator + data
    binary_data = ''.join(f"{byte:08b}" for byte in data_with_length)
    binary_data += '0' * ((3 - len(binary_data) % 3) % 3)

    pixels = list(img.getdata())
    data_index = 0
    new_pixels = []

    for pixel in pixels:
        if data_index >= len(binary_data):
            new_pixels.append(pixel)
            continue
        r, g, b = pixel
        r = (r & ~1) | int(binary_data[data_index])
        data_index += 1
        if data_index < len(binary_data):
            g = (g & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            b = (b & ~1) | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    return img


def reveal_data(image_path):
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    binary_data = ''

    for pixel in pixels:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)

    length_indicator = binary_data[:32]
    data_length = int(length_indicator, 2)
    required_bits = 32 + data_length * 8
    binary_data = binary_data[:required_bits]

    data = bytearray()
    for i in range(32, len(binary_data), 8):
        byte = binary_data[i:i + 8]
        if len(byte) < 8:
            break
        data.append(int(byte, 2))

    return bytes(data)
# ==============================================
# Enhanced GUI with Proper Cipher Integration
# ==============================================
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Steganography Tool")
        self.root.geometry("800x600")
        self.root.configure(bg="#2f4155")

        self.filename = ""
        self.img_display = None

        self._setup_gui()

    def _setup_gui(self):
        tk.Label(self.root, text="Secure Steganography Tool", bg="#2f4155", fg="white",
                 font=("Arial", 20, "bold")).pack(pady=10)
        tk.Label(self.root, text="Passphrase:", bg="#2f4155", fg="white",
                 font=("Arial", 12)).place(x=20, y=60)
        self.passphrase_entry = tk.Entry(self.root, width=40, show="*")
        self.passphrase_entry.place(x=150, y=60)

        tk.Label(self.root, text="Cipher Algorithm:", bg="#2f4155", fg="white",
                 font=("Arial", 12)).place(x=20, y=100)
        self.cipher_var = tk.StringVar()
        cipher_dropdown = ttk.Combobox(self.root, textvariable=self.cipher_var,
                                       values=["AES-256", "ChaCha20"], state="readonly", width=30)
        cipher_dropdown.place(x=150, y=100)
        cipher_dropdown.set(" Select cipher")

        self.image_frame = tk.Frame(self.root, bd=3, bg="black", width=800, height=600, relief=tk.SUNKEN)
        self.image_frame.place(x=50, y=150)
        self.image_label = tk.Label(self.image_frame, bg="black")
        self.image_label.pack(fill=tk.BOTH, expand=True)

        tk.Label(self.root, text="Message:", bg="#2f4155", fg="white",
                 font=("Arial", 12)).place(x=400, y=150)
        self.text1 = tk.Text(self.root, wrap=tk.WORD, width=40, height=15)
        self.text1.place(x=400, y=180)

        tk.Button(self.root, text="Open Image", command=self._open_image, width=15, bg="#4CAF50",
                  fg="white", font=("Arial", 10, "bold")).place(x=50, y=480)
        tk.Button(self.root, text="Hide Data", command=self._hide_data, width=15, bg="#2196F3",
                  fg="white", font=("Arial", 10, "bold")).place(x=200, y=480)
        tk.Button(self.root, text="Reveal Data", command=self._reveal_data, width=15, bg="#FFC107",
                  fg="black", font=("Arial", 10, "bold")).place(x=350, y=480)
        tk.Button(self.root, text="Clear", command=self._clear, width=15, bg="#F44336",
                  fg="white", font=("Arial", 10, "bold")).place(x=500, y=480)
        tk.Button(self.root, text="Exit", command=self.root.quit, width=15, bg="#9C27B0",
                  fg="white", font=("Arial", 10, "bold")).place(x=650, y=480)

    def _open_image(self):
        self.filename = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.bmp;*.jpg;*.jpeg")])
        if self.filename:
            img = Image.open(self.filename)
            img.thumbnail((600, 600))
            self.img_display = ImageTk.PhotoImage(img)
            self.image_label.config(image=self.img_display)

    def _hide_data(self):
        if not self.filename:
            messagebox.showwarning("Warning", "Please select an image first!")
            return

        passphrase = self.passphrase_entry.get().strip()
        if not passphrase:
            messagebox.showwarning("Warning", "Please enter a passphrase!")
            return

        message = self.text1.get("1.0", tk.END).strip().encode('utf-8')
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to hide!")
            return

        cipher = self.cipher_var.get()
        key = simple_password_hash(passphrase)
        encrypted_message = None

        if cipher == "AES-256":
            aes = AES256()
            encrypted_message = aes.encrypt(message, key)
        elif cipher == "ChaCha20":
            nonce = key[:12]  # Derive nonce from key
            chacha = ChaCha20(key, nonce)
            encrypted_message = chacha.encrypt(message)
        else:
            messagebox.showwarning("Warning", "Please select a cipher algorithm!")
            return

        img = hide_data(self.filename, encrypted_message)
        if img:
            save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                     filetypes=[("PNG Files", "*.png")])
            if save_path:
                img.save(save_path)
                messagebox.showinfo("Success", f"Data hidden and saved to {save_path}")

    def _reveal_data(self):
        if not self.filename:
            messagebox.showwarning("Warning", "Please select an image first!")
            return

        passphrase = self.passphrase_entry.get().strip()
        if not passphrase:
            messagebox.showwarning("Warning", "Please enter a passphrase!")
            return

        cipher = self.cipher_var.get()
        key = simple_password_hash(passphrase)
        decrypted_data = reveal_data(self.filename)

        if decrypted_data:
            try:
                if cipher == "AES-256":
                    aes = AES256()
                    decrypted_message = aes.decrypt(decrypted_data, key)
                elif cipher == "ChaCha20":
                    nonce = key[:12]  # Derive nonce from key
                    chacha = ChaCha20(key, nonce)
                    decrypted_message = chacha.decrypt(decrypted_data)
                else:
                    messagebox.showwarning("Warning", "Please select a cipher algorithm!")
                    return

                decrypted_message_str = decrypted_message.decode('utf-8')
                self.text1.delete("1.0", tk.END)
                self.text1.insert("1.0", decrypted_message_str)
            except UnicodeDecodeError:
                messagebox.showerror("Error", "Decryption failed. Incorrect passphrase or cipher settings.")

    def _clear(self):
        self.passphrase_entry.delete(0, tk.END)
        self.cipher_var.set("Select cipher")
        self.text1.delete("1.0", tk.END)
        self.image_label.config(image="")
        self.filename = ""
        
root = tk.Tk()
app = SteganographyApp(root)
root.mainloop()