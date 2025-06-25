import json
import numpy as np
from typing import Tuple
import sqlite3
# import os
    
# SQLite
class LocalServer:
    def __init__(self, db_path="crps.db"):
        self.__connection = sqlite3.connect(db_path)
        self.__cursor = self.__connection.cursor()
        self.__db_table = "crps"
        self.__create_table_if_not_exists()

    def __create_table_if_not_exists(self):
        stmt = f"""
        CREATE TABLE IF NOT EXISTS {self.__db_table} (
            id INTEGER PRIMARY KEY,
            gid INTEGER,
            challenge TEXT,
            response TEXT
        )
        """
        self.__cursor.execute(stmt)
        self.__connection.commit()

    def dropCRP(self):
        stmt = f"DELETE FROM {self.__db_table}"
        self.__cursor.execute(stmt)
        self.__connection.commit()

    def __getResponse(self, iot_id: int):
        stmt = f"SELECT response FROM {self.__db_table} WHERE id = ?"
        self.__cursor.execute(stmt, (iot_id,))
        row = self.__cursor.fetchone()
        if row is None:
            raise ValueError("ID not found.")
        response = bytes.fromhex(row[0])
        return response

    def __getChallenge(self, iot_id: int):
        stmt = f"SELECT challenge FROM {self.__db_table} WHERE id = ?"
        self.__cursor.execute(stmt, (iot_id,))
        row = self.__cursor.fetchone()
        if row is None:
            raise ValueError("ID not found.")
        challenge = np.array(json.loads(row[0]))
        return challenge

    def registerCRP(self, id, gid, challenge: np.ndarray, response: bytes):
        stmt = f"INSERT OR REPLACE INTO {self.__db_table} (id, gid, challenge, response) VALUES (?, ?, ?, ?)"
        data = (id, gid, json.dumps(challenge.tolist()), response.hex())
        self.__cursor.execute(stmt, data)
        self.__connection.commit()
        return self.__cursor.rowcount

    def sendCRP(self, device_id):
        challenge = self.__getChallenge(device_id)
        response = self.__getResponse(device_id)
        return (device_id, challenge, response)

# class LocalServerPi():
#     def __init__(self):
#         self.CRPs = {}
    
#     def registerCRP(
#         self, id, gid, challenge: np.ndarray, response: bytes
#     ):
#         self.CRPs[id] = (gid, challenge, response)
    
#     def sendCRP(self, device_id):
#         device_crp = (device_id, self.CRPs[device_id][1], self.CRPs[device_id][2])
#         return device_crp
    
#     def dropCRP(self):
#         return

# MySQL
# class LocalServer:
#     def __init__(self):
#         load_dotenv()
#         self.__connection = mysql.connector.connect(
#             database=os.getenv("DB_NAME"),
#             host=os.getenv("DB_HOST"),
#             user=os.getenv("DB_USERNAME"),
#             password=os.getenv("DB_PASSWORD"),
#         )
#         self.__cursor = self.__connection.cursor(prepared=True)
#         self.__db_table = "crps"

#     def dropCRP(self):
#         stmt = f"DELETE FROM crps"
#         self.__cursor.execute(stmt)
#         self.__connection.commit()

#     def __getResponse(self, iot_id: int):
#         stmt = f"SELECT response FROM crps WHERE id = %s"
#         self.__cursor.execute(stmt, (iot_id,))
#         response = bytes.fromhex(self.__cursor.fetchall()[0][0])

#         return response

#     def __getChallenge(self, iot_id: int):
#         stmt = f"SELECT challenge FROM crps WHERE id = %s"
#         self.__cursor.execute(stmt, (iot_id,))
#         challenge = np.array(json.loads(self.__cursor.fetchall()[0][0]))

#         return challenge

#     def registerCRP(
#         self, id, gid, challenge: np.ndarray, response: bytes
#     ):  # assume to perform over secure channel
#         stmt = (
#             f"INSERT INTO crps (id, gid, challenge, response) VALUES (%s, %s, %s, %s)"
#         )
#         data = (id, gid, json.dumps(challenge.tolist()), response.hex())
#         self.__cursor.execute(stmt, data)
#         self.__connection.commit()

#         return self.__cursor.rowcount
    
#     def sendCRP(self, device_id):
#         device_crp = (device_id, self.__getChallenge(device_id), self.__getResponse(device_id))
#         return device_crp
    
    # def __getGID(self, iot_id: int):
    #     stmt = f"SELECT gid FROM crps WHERE id = %s"
    #     self.__cursor.execute(stmt, (iot_id,))

    #     return self.__cursor.fetchone()[0]

    # def genEnrollReq(self, id: int, pairing_id: int):
    #     challenge: np.ndarray = np.array(json.loads(self.__getChallengeJSON(id)))
    #     pairing_challenge: np.ndarray = np.array(
    #         json.loads(self.__getChallengeJSON(pairing_id))
    #     )
    #     nonce: bytes = secrets.token_bytes(32)

    #     return (id, challenge, pairing_id, pairing_challenge, nonce)

    # def resToAuth(
    #     self,
    #     id: int,
    #     pairing_id: int,
    #     AUTHX: Tuple[bytes, bytes],
    #     pairing_AUTHX: Tuple[bytes, bytes],
    #     m: bytes,
    #     n: bytes,
    # ):
    #     (auth, nonce) = AUTHX
    #     (pairing_auth, pairing_nonce) = pairing_AUTHX

    #     response = self.__getResponse(id)
    #     pairing_response = self.__getResponse(pairing_id)

    #     auth_prime = sha256(
    #         (int.from_bytes(response) ^ int.from_bytes(m)).to_bytes(32)
    #     ).hexdigest()
    #     pairing_auth_prime = sha256(
    #         (int.from_bytes(pairing_response) ^ int.from_bytes(n)).to_bytes(32)
    #     ).hexdigest()

    #     if not (auth == auth_prime and pairing_auth == pairing_auth_prime):
    #         raise Exception("Enrollment failed: invalid AUTH to Local server")

    #     p_1 = sha256(response + pairing_id.to_bytes(16)).digest()
    #     pairing_p_1 = sha256(pairing_response + id.to_bytes(16)).digest()

    #     p_2 = sha256(p_1).digest()
    #     pairing_p_2 = sha256(pairing_p_1).digest()

    #     phi = (int.from_bytes(p_1) ^ int.from_bytes(pairing_p_1)).to_bytes(32)
    #     pairing_phi = (int.from_bytes(p_2) ^ int.from_bytes(pairing_p_2)).to_bytes(32)

    #     X = AESCipher(sha256(response).digest()).encrypt(
    #         f"{nonce.hex()}||||{pairing_phi.hex()}"
    #     )
    #     pairing_X = AESCipher(sha256(pairing_response).digest()).encrypt(
    #         f"{pairing_nonce.hex()}||||{phi.hex()}"
    #     )

    #     return (X, pairing_X)

    # def __genGroupKey(self, gid: int):
    #     query = "SELECT GROUP_CONCAT(response SEPARATOR '') AS concatenated_responses FROM crps WHERE gid = %s"
    #     self.__cursor.execute(query, (gid,))
    #     concat_response = self.__cursor.fetchone()[0]
    #     group_key = sha256(bytes.fromhex(concat_response)).digest()

    #     return group_key

    # def sendGroupKey(self, iot_id: int):
    #     gid = self.__getGID(iot_id)
    #     iot_response = self.__getResponse(iot_id)
    #     response_key = sha256(iot_response).digest()
    #     iot_challenge_json = self.__getChallengeJSON(iot_id)
    #     gk = self.__genGroupKey(gid)

    #     timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    #     # Generate packet to send to IoT
    #     packet = f"{gk.hex()}||||{timestamp}"

    #     # Encrypted packet to send
    #     enc_packet = AESCipher(response_key).encrypt(packet)

    #     # Message into HMAC generation
    #     concat_msg = f"{enc_packet.hex()}{iot_challenge_json}"

    #     # Generate HMAC (Enc-Then-MAC) (HMAC-SHA256(enc_packet || iot_challenge))
    #     mac = hmac.new(response_key, concat_msg.encode(), sha256).digest()

    #     # Challenge to send
    #     challenge = np.array(json.loads(iot_challenge_json))

    #     return (enc_packet, mac, challenge)
