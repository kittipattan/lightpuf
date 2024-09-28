from pypuf.simulation import ArbiterPUF
import os
import secrets
from utils.aes256 import AESGCMCipher, AESCBCCipher
from utils.measurement import measure_computation_cost
from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
import numpy as np
from typing import Tuple
import time
import blake3 as b3
import struct
import random
from pypuf.io import random_inputs


class IoTPi:
    def __init__(self, id: int, gid: int, seed: int, data: str, n_challenge=64) -> None:
        # Our scheme
        self.id = id
        self.gid = gid
        self.token = None
        self.secret = None
        self.partialKey = None
        self.data = data.encode()

        # PUF-based authentication
        self.puf = ArbiterPUF(n=n_challenge, seed=seed)
        self.gk: bytes = None

        self.CRP = None
        # self.tmpPairing_challenge = None
        # self.nonces = {"m": None, "x": None, "n": None, "pairing_n": None}
        self.nonces = {"m": None, "n": None}
        # self.tmpID = -1
        self.localDatabase = {}
        self.timestamp = None
        # self.pairing_timestamp = None
        # self.pairing_id: int = -1
        # self.p_1 = None
        self.responseKey = None

    def genResponse(self, challenge):
        response = self.puf.eval(challenge)
        response = np.abs(response)

        return int("".join(str(r) for r in response), 2).to_bytes(32)

    # PHASE 1: System Initialization
    # Fog only

    # PHASE 2: Key Exchange
    def recvKeys(self, pkt: Tuple[np.ndarray, int, bytes, float, bytes, bytes]):
        (challenge, pairing_id, nonce_key, timestamp, nonce_gcm, enc_msg) = pkt

        # Validate timestamp
        if abs(time.time() - timestamp) >= 60:
            raise Exception("Timestamp is too old or too far in the future")

        # Device generates the response and cached
        self.CRP = (challenge, self.genResponse(challenge))

        # Derive the key
        self.responseKey = b3.blake3((self.CRP[1] + self.id.to_bytes(4) + nonce_key)).digest()

        # Decrypt the msg
        assoc_data = (
            challenge.tobytes()
            + pairing_id.to_bytes(4)
            + nonce_key
            + struct.pack("d", timestamp)
            + nonce_gcm
        )
        secret = AESGCMCipher(self.responseKey).decrypt(
            nonce_gcm, enc_msg, assoc_data
        )

        # Store pairKey with device pairing_id
        self.localDatabase[pairing_id] = secret[:32]

        # Store group key
        self.gk = secret[32:]

    # PHASE 3: Group Authentication
    # Leader and Fog

    # PHASE 4: Data Authentication
    def recvSecret(self, pkt: Tuple[bytes, bytes, float, bytes]):
        (enc_secret, partial_key, timestamp, mac) = pkt

        # Validate timestamp
        if abs(time.time() - timestamp) >= 300:
            raise Exception("Timestamp is too old or too far in the future")

        # Verify MAC
        mac_data = (
            self.id.to_bytes(4) + enc_secret + partial_key + struct.pack("d", timestamp)
        )
        mac_device = b3.blake3(mac_data, key=self.gk).digest()
        
        # print(f"iot gk: {self.gk}")
        # print(f"mac {self.id}: {mac}")
        # print(f"mac_device {self.id}: {mac_device}")
        
        if mac_device != mac:
            raise Exception("IoT MAC mismatch")

        # Decrypt secret
        self.secret = AESCBCCipher(self.gk).decrypt(enc_secret)
        self.partialKey = partial_key

    # 4. Token Generation
    def generateToken(self):
        data = self.gid.to_bytes(4) + self.id.to_bytes(4) + self.data + self.partialKey
        token = b3.blake3(data, key=self.secret).digest()

        return token

    def createPacket(self):
        # start_time = timeit.default_timer()
        # (self.id, self.gid, self.data, self.partialKey, self.generateToken())
        # print(f"Token gen within: {(timeit.default_timer() - start_time)*1000} ms")

        return (self.gid, self.id, self.data, self.partialKey, self.generateToken())

    # Recovery phase
    def updateGroupKey(self, pkt: Tuple[bytes, int, float, bytes]):
        (enc_msg, leader_id, timestamp, nonce_gcm) = pkt

        # Validate timestamp
        if abs(time.time() - timestamp) >= 60:
            raise Exception("Timestamp is too old or too far in the future")

        try:
            # Decrypt the message
            assoc_data = leader_id.to_bytes(4) + struct.pack("d", timestamp) + nonce_gcm
            msg = AESGCMCipher(self.localDatabase[leader_id]).decrypt(
                nonce_gcm, enc_msg, assoc_data
            )

            # Store new Group Key, DX, secret
            self.gk = msg[:32]
            self.partialKey = msg[32:64]
            self.secret = msg[64:]
        except:
            raise Exception(f"IoT {self.id}: updateGroupKey Decryption error")

    # def recvGroupKey(self, pkt: Tuple[bytes, bytes, int]):
    #     (enc_msg, mac_leader, leader_id) = pkt
    #     sk_puf = self.localDatabase[leader_id]

    #     # Message into HMAC generation
    #     concat_msg = f"{enc_msg.hex()}{leader_id}"

    #     # Verify MAC
    #     mac_iot = hmac.new(sk_puf, concat_msg.encode(), sha256).digest()
    #     if not hmac.compare_digest(mac_leader, mac_iot):
    #         assert Exception("Leader MAC invalid")

    #     # Decrypt the received packet
    #     packet = AESCipher(sk_puf).decrypt(enc_msg)
    #     (gk, timestamp) = packet.split("||||")

    #     # Validate timestamp
    #     timestamp = datetime.strptime(timestamp, "%m/%d/%Y, %H:%M:%S")
    #     timestamp_iot = datetime.now()

    #     # current_timestamp - timestamp
    #     if (timestamp_iot - timestamp).total_seconds() > 60:
    #         assert Exception("Leader timestamp exceed limit")

    #     # Store Group Key
    #     self.gk = bytes.fromhex(gk)

    def recvSecFromLeader(self, leader_id: int, packet: Tuple[bytes, bytes]):
        # (enc_secret, partial_ciphered_key) = packet
        # secret = AESCipher(self.gk).decrypt(enc_secret)
        # self.secret = bytes.fromhex(secret)
        # self.partialKey = partial_ciphered_key
        pass


def main():
    # Measure computation cost of each operation

    # Parameter used
    data = random.randbytes(200)
    iot = IoTPi(1, 1, 1, data.hex())
    id = iot.id
    curve = Curve.get_curve("Curve25519")
    ecc_point = curve.generator
    ecc_int = secrets.randbits(256)
    ecc_privkey = ECPrivateKey(secrets.randbits(256), curve)
    ecc_pubkey = ecc_privkey.get_public_key()
    ecc_privpub = (ecc_privkey.d * ecc_pubkey.W).x.to_bytes(32)
    ecc_salt = os.urandom(16)
    ecc_field = curve.field
    aes_key = os.urandom(32)
    aes_nonce = os.urandom(12)
    aes_assoc_data = struct.pack("d", time.time())
    puf_challenge = random_inputs(64, 256, id)
    puf_challenge = (1 - puf_challenge) // 2

    # Hashing operations
    measure_computation_cost(b3.blake3(data).digest, "T_h (Hashing operation)", 100000)

    # ECC point addition
    measure_computation_cost(
        curve.add_point, "T_ea (ECC point addition)", 1000, ecc_point, ecc_point
    )

    # ECC point multiplication
    measure_computation_cost(
        curve.mul_point, "T_em (ECC point multiplication)", 1000, ecc_int, ecc_point
    )

    # Modular multiplicative inverse
    measure_computation_cost(
        lambda x, p: pow(x, -1, p),
        "T_mi (Modular multiplicative inverse)",
        100000,
        ecc_int,
        ecc_field,
    )

    # Symmetric encryption
    measure_computation_cost(
        AESGCMCipher(aes_key).encrypt,
        "T_s (Symmetric encryption)",
        100000,
        aes_nonce,
        data,
        aes_assoc_data,
    )

    # Bilinear pairing

    # Fuzzy extraction

    # PUF response generation
    measure_computation_cost(
        iot.puf.eval, "T_PUF (PUF response generation)", 1000, puf_challenge
    )

    # Key derivation function
    measure_computation_cost(
        b3.blake3(
            (ecc_privpub + ecc_salt),
            derive_key_context="LightPUF IoT 2024-09-26 01:47:29 Derive key in Group Authentication",
        ).digest,
        "T_KDF (Key Derivation Function)",
        100000,
    )

    # Message Authentication Code (MAC) function
    measure_computation_cost(
        b3.blake3(data, key=aes_key).digest,
        "T_MAC (Message Authentication Code function)",
        100000,
    )
    
if __name__ == "__main__":
    main()
