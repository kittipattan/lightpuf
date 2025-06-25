from utils.nizkp import schnorr_nizk_proof, schnorr_nizk_verify
from iot_rasppi import IoTPi
from utils.aes256 import AESCBCCipher, AESGCMCipher
from typing import Tuple
import os
import time
import struct
from typing import List, Tuple
from ecdsa import SigningKey, VerifyingKey, NIST256p, ECDH
import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
import pickle


class LeaderPi(IoTPi):
    def __init__(self, id, gid, seed, data, n_challenge=64):
        super().__init__(id, gid, seed, data, n_challenge)
        # NIZKP
        self.curve = NIST256p
        self.G = self.curve.generator
        self.n = self.curve.order
        self.prk = SigningKey.generate(curve=self.curve, hashfunc=hashlib.sha256)
        self.PK = self.prk.verifying_key
        self.ecdhPrK = None
        self.ecdhPK = None
        self.ssk: bytes = None
        self.encSecret: bytes = None

    # PHASE 3: Group Key Generation
    def sendGroupKey(self, group: List[IoTPi]):
        K = os.urandom(64)
        self.gk = K[:32]
        self.mk = K[32:]

        for iot in group:
            if iot.id == self.id:
                continue
            timestamp = time.time()
            n_gcm = os.urandom(12)
            assoc_data = (
                self.id.to_bytes(4)
                + iot.id.to_bytes(4)
                + struct.pack("d", timestamp)
                + n_gcm
            )
            encrypted_msg = AESGCMCipher(self.localDatabase[iot.id]).encrypt(
                nonce=n_gcm, plaintext=K, associated_data=assoc_data
            )
            packet = (encrypted_msg, self.id, timestamp, n_gcm)
            iot.recvGroupKey(packet)

    # PHASE 4: Group Authentication
    def genProof(self):
        self.ecdhPrK = SigningKey.generate(curve=self.curve, hashfunc=hashlib.sha256)
        self.ecdhPK = self.ecdhPrK.verifying_key
        message = self.id.to_bytes(4) + self.ecdhPK.to_string()
        V, r = schnorr_nizk_proof(
            self.prk, self.PK, message
        )

        return (self.PK, self.id, self.ecdhPK, V, r)

    def verifyProof(self, fog_proof):
        fog_pk, fog_ecdhPK, fog_V, fog_r = fog_proof

        if not schnorr_nizk_verify(fog_V, fog_r, fog_pk, fog_ecdhPK.to_string()):
            raise Exception("Fog NIZKP Proof is invalid")

        salt = fog_V.to_bytes()[:16]
        self.deriveSSK(fog_ecdhPK, salt)

    def deriveSSK(self, sharing_PK, salt):
        # x = (self.curve.mul_point(self.prk.d, sharing_PK.W)).x.to_bytes(32)
        x = (
            (self.ecdhPrK.privkey.secret_multiplier * sharing_PK.pubkey.point)
            .x()
            .to_bytes(32)
        )
        # self.ssk = b3.blake3(
        #     (x + salt),
        #     derive_key_context="LightPUF SSK Derivation 2024-09-26 21:58:05 derive SSK between Leader and Fog",
        # ).digest()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"LightPUF IoT 2024-09-26 01:47:29 Derive key in Group Authentication",
            backend=default_backend(),
        )
        self.ssk = hkdf.derive(x)
        # print(f"leader ssk: {self.ssk}")

    # PHASE 5: Data Authentication and Integrity Verification
    # 3. Secret distribution
    def distributeSecret(
        self,
        packet: Tuple[float, bytes, bytes],
        group: List[IoTPi],
    ):
        timestamp_fog, n_gcm, enc_message = packet

        # Validate timestamp
        if abs(time.time() - timestamp_fog) >= 300:
            raise Exception("Timestamp is too old or too far in the future")

        assoc_data = self.id.to_bytes(4) + struct.pack("d", timestamp_fog) + n_gcm
        message = AESGCMCipher(self.ssk).decrypt(
            nonce=n_gcm, ciphertext=enc_message, associated_data=assoc_data
        )
        self.secret = message[:32]
        dxs = pickle.loads(message[32:])

        enc_group_secret_device = AESCBCCipher(self.gk).encrypt(self.secret)
        for msg, iot in zip(dxs, group):
            device_id = msg[0]
            dx = msg[1]
            if device_id == self.id:
                self.partialKey = dx
                continue

            timestamp = time.time()
            mac_data = (
                iot.id.to_bytes(4)
                + enc_group_secret_device
                + dx
                + struct.pack("d", timestamp)
            )
            mac = hmac.new(key=self.mk, msg=mac_data, digestmod=hashlib.sha256).digest()

            iot.recvSecret((enc_group_secret_device, dx, timestamp, mac))

    # Our scheme
    # def recvSecFromFog(self, enc_packet):
    #     (secret, ciphered_keys) = AESCipher(self.ssk).decrypt(enc_packet).split("||||")
    #     secret = bytes.fromhex(secret)
    #     ciphered_keys = json.loads(ciphered_keys)
    #     ciphered_keys = list(map(lambda ck: bytes.fromhex(ck), ciphered_keys))

    #     self.secret = secret
    #     self.partialKey = ciphered_keys[0]
    #     self.encSecret = AESCipher(self.gk).encrypt(f"{self.secret.hex()}")

    #     return (secret, ciphered_keys)

    # def sendSecToIoT(self, iot_id: int, secret: bytes, partial_ciphered_key: bytes):
    #     return (self.encSecret, partial_ciphered_key)
