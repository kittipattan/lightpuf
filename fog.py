from utils.aes256 import AESGCMCipher, AESCBCCipher
from ecdsa import SigningKey, VerifyingKey, NIST256p, ECDH
from utils.nizkp import schnorr_nizk_proof, schnorr_nizk_verify
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import List, Tuple
from iot_rasppi import IoTPi
from leader_rasppi import LeaderPi
import os
import numpy as np
import hmac
import hashlib
import time
import struct
import pickle
# import json
# from dotenv import load_dotenv
# from azure.storage.blob import BlobServiceClient

class Fog:
    def __init__(self):
        self.curve = NIST256p
        self.prk = SigningKey.generate(curve=self.curve, hashfunc=hashlib.sha256)
        self.PK = self.prk.verifying_key
        self.ecdhPrK = None
        self.ecdhPK = None
        self.ssk = None
        self.salt = None

        # Local Database
        self.iotAuthDB = {}  # store gid, enc_secret, partial_ciphered_key (20%)
        self.__iotPartialKeyDB = (
            {}
        )  # store id, partial_ciphered_key (that's been sent to IoT id)
        self.iotTempData = {}  # id : (iot_gid, iot_data, iot_partialKey, iot_token)
        self.aggregatedData = {}  # gid : [iot_data, iot_data, ...]

    # PHASE 1: System initialization    
    def deriveDeviceKey(
        self,
        device_crps: List[Tuple[int, np.ndarray, bytes]],
        group: List[IoTPi]
    ):
        # Retrieve CRP for Leader and IIoT device from Local Server via secure channel
        leader = group[0]
        leader_id = device_crps[0][0]
        leader_challenge = device_crps[0][1]
        leader_response = device_crps[0][2]
        # group_key = os.urandom(32)
        
        for device_crp, device in zip(device_crps, group):
            device_id = device_crp[0]
            device_challenge = device_crp[1]
            device_response = device_crp[2]

            # Generate a key for a pair of leader and device
            pair_key = os.urandom(32)

            # Generate nonces
            n_key = os.urandom(32)
            n_gcm = os.urandom(12)

            # Derive session key for devices
            leader_key = hashlib.sha256((leader_response + leader_id.to_bytes(4) + n_key)).digest()
            device_key = hashlib.sha256((device_response + device_id.to_bytes(4) + n_key)).digest()

            # Get the current timestamp
            timestamp = time.time()

            # Encrypt keys for devices
            enc_keys_leader = AESGCMCipher(leader_key).encrypt(
                n_gcm,
                (pair_key),
                (
                    leader_challenge.tobytes()
                    + device_id.to_bytes(4)
                    + n_key
                    + struct.pack("d", timestamp)
                    + n_gcm
                ),
            )

            enc_keys_device = AESGCMCipher(device_key).encrypt(
                n_gcm,
                (pair_key),
                (
                    device_challenge.tobytes()
                    + leader_id.to_bytes(4)
                    + n_key
                    + struct.pack("d", timestamp)
                    + n_gcm
                ),
            )

            leader_pkt = (
                leader_challenge,
                device_id,
                n_key,
                timestamp,
                n_gcm,
                enc_keys_leader,
            )
            
            device_pkt = (
                device_challenge,
                leader_id,
                n_key,
                timestamp,
                n_gcm,
                enc_keys_device,
            )
            
            leader.recvPairKey(leader_pkt)
            device.recvPairKey(device_pkt)

    # PHASE 2: Key Exchange
    # IoT devices only
    
    # PHASE 3: Group Key Generation
    # IoT devices only

    # PHASE 4: Group Authentication
    def genProof(self):
        self.ecdhPrK = SigningKey.generate(curve=self.curve, hashfunc=hashlib.sha256)
        self.ecdhPK = self.ecdhPrK.verifying_key
        message = self.ecdhPK.to_string()
        V, r = schnorr_nizk_proof(self.prk, self.PK, message)
        self.salt = V.to_bytes()[:16]
        
        return (self.PK, self.ecdhPK, V, r)

    def verifyProof(self, leader_proof):
        leader_pk, leader_id, leader_ecdhPK, leader_V, leader_r = leader_proof
        message = leader_id.to_bytes(4) + leader_ecdhPK.to_string()
        
        if not schnorr_nizk_verify(leader_V, leader_r, leader_pk, message):
            raise Exception("Leader NIZKP Proof is invalid")
        
        self.deriveSSK(leader_ecdhPK, self.salt)
        
    def deriveSSK(self, sharing_PK, salt):
        # x = (self.curve.mul_point(self.prk.d, sharing_PK.W)).x.to_bytes(32)
        x = (self.ecdhPrK.privkey.secret_multiplier * sharing_PK.pubkey.point).x().to_bytes(32)
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

    # PHASE 5: Data Authentication and Integrity Verification
    def genSec(self, group: List[IoTPi]):
        if not isinstance(group[0], LeaderPi):
            raise Exception("Secret generation error")
        gid = group[0].gid
        leader_id = group[0].id

        # 1. Secret Generation
        group_secret = os.urandom(32)       # SGID
        # group_secret = b'\x0cg\x1dcm\x86p\xfbo\xa5-x\x9d9g\xfe,G\xd5\xbe\x85\xef\xafsY6\x9a\x7f\xfb\x91\x1f\xd2'
        pre_key = os.urandom(32)   # k
        # intermediary_key = b'M\x84\x179\xf8/\xb4\xb5w!\xec\xf5v\xc6\xbd\xd1\xd3\x05s\xbc\x18T\xda\xaeI\xb8\xa1H5Ir\x07'
        database_key = hmac.new(key=hashlib.sha256(self.prk.to_string()).digest(), msg=pre_key, digestmod=hashlib.sha256).digest()
        enc_group_secret_database = AESCBCCipher(database_key).encrypt(group_secret)
        enc_pre_key = AESCBCCipher(hashlib.sha256(gid.to_bytes(4)).digest()).encrypt(pre_key)
        timestamp = time.time()

        # 2. AES Key Encryption and Key Splitting
        # Partition AES_cipher (8 for IoTs : 2 for storing in Fog database)
        index_to_split = round(len(enc_pre_key) * 0.8)
        partial_enc_pre_key = enc_pre_key[:index_to_split]
        dxs: List[bytes] = []

        # Store in database
        self.iotAuthDB[gid] = (enc_group_secret_database, enc_pre_key[index_to_split:])

        for i, device in enumerate(group):
            start = round((i * len(partial_enc_pre_key)) / len(group))
            end = round(((i + 1) * len(partial_enc_pre_key)) / len(group))

            # DX
            dx = partial_enc_pre_key[start:end]

            # Fog stores H(DX) in own database
            self.__iotPartialKeyDB[device.id] = hashlib.sha256(dx).digest()

            dxs.append(
                (device.id, dx)
            )

        n_gcm = os.urandom(12)
        timestamp = time.time()
        message = group_secret + pickle.dumps(dxs) # Here
        assoc_data = (leader_id.to_bytes(4) + struct.pack("d", timestamp) + n_gcm)
        enc_message = AESGCMCipher(self.ssk).encrypt(
            n_gcm, message, assoc_data
        )

        # Send to Leader
        return (timestamp, n_gcm, enc_message)

    def recvData(self, iot_packet):
        (iot_gid, iot_id, iot_timestamp, iot_partialKey, iot_token, iot_data) = iot_packet

        if not (iot_gid in self.iotAuthDB):
            assert Exception(f"IoT with gid {iot_gid} is invalid")

        if not (iot_id in self.__iotPartialKeyDB):
            assert Exception(f"IoT id {iot_id} is invalid")
            
        if abs(time.time() - iot_timestamp) >= 120:
            assert Exception(f"IoT id {iot_id} data is not fresh")

        if hashlib.sha256(iot_partialKey).digest() != self.__iotPartialKeyDB[iot_id]:
            assert Exception(f"IoT partial ciphered key is invalid")

        # Temporary store IoT partial ciphered key and wait to be 100% full
        self.iotTempData[iot_id] = (iot_gid, iot_timestamp, iot_partialKey, iot_token, iot_data)

    def verifyToken(self, group: List[IoTPi]):
        iot_gid = group[0].gid

        enc_aes_key: bytes = b""
        for iot in group:
            enc_aes_key += self.iotTempData[iot.id][2]  # from IoT
        enc_aes_key += self.iotAuthDB[iot_gid][1]  # from Fog

        hashed_gid = hashlib.sha256(
            iot.gid.to_bytes(4)
        ).digest()  # decrypt key with hash value of GID

        aes_key = AESCBCCipher(hashed_gid).decrypt(
            enc_aes_key
        )  # to decrypt the ciphered secret
        
        aes_key = b'M\x84\x179\xf8/\xb4\xb5w!\xec\xf5v\xc6\xbd\xd1\xd3\x05s\xbc\x18T\xda\xaeI\xb8\xa1H5Ir\x07'

        # Decrypt the enc_secret in database
        group_secret = AESCBCCipher(aes_key).decrypt(self.iotAuthDB[iot_gid][0])

        # Token verification
        for iot in group:
            self.verifySingleToken(iot, group_secret, self.aggregatedData)
            # del self.iotTempData[iot.id]
            
    def verifySingleToken(self, iot: IoTPi, group_secret: bytes, aggregated_data: List[str]):
        (iot_gid, iot_timestamp, iot_partialKey, iot_token, iot_data) = self.iotTempData[iot.id]
        
        iot_msg = (
            iot_gid.to_bytes(4) + iot.id.to_bytes(4) + struct.pack("d", iot_timestamp) + iot_partialKey + iot_data
        )
        
        # iot_token_fog = b3.blake3(iot_msg, key=group_secret).digest()
        # iot_token_fog = hashlib.blake2b(iot_msg, digest_size=32, key=group_secret, usedforsecurity=True).digest()
        iot_token_fog = hmac.new(key=group_secret, msg=iot_msg, digestmod=hashlib.sha256).digest()

        # if iot_token != iot_token_fog:
        if not hmac.compare_digest(iot_token, iot_token_fog):
            assert Exception(
                f"     Data Authentication failed: IoT {iot.id} Token invalid"
            )
        try:
            self.aggregatedData[iot.gid].append(iot.data.decode())
            # aggregated_data.append(iot.data.decode())
        except KeyError:
            self.aggregatedData[iot.gid] = [iot.data.decode()]

    # def uploadToCloud(self, fog_nodes, devices_per_node, fog_id, gid, aggregated_data):
    #     aggregated_iot_data = {
    #         "fog_node_id": fog_id,
    #         "aggregated_data": aggregated_data,
    #     }

    #     try:
    #         load_dotenv()

    #         # initialize a connection to Azure Blob Storage
    #         connect_str = os.getenv("AZURE_API")  # to add connection
    #         blob_service_client = BlobServiceClient.from_connection_string(connect_str)
    #         container_name = "iiot-data-authentication-to-cloud"
    #         blob_name = f"our_scheme/fog_no_{fog_nodes}/device_no_{devices_per_node}/aggregated_data_{gid}.json"

    #         # convert aggregated data to JSON
    #         data = json.dumps(aggregated_iot_data)
    #         # print(f"\n{data}\n")

    #         # upload data
    #         blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    #         blob_client.upload_blob(data, overwrite=True)
    #         print(f"Uploaded aggregated data of fog node {gid} to Azure Blob Storage.")

    #     except Exception as e:
    #         print(f"Error uploading data for fog node: {e}")
