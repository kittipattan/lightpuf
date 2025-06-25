import secrets
import sys
from ecdsa import SigningKey, VerifyingKey, NIST256p, ECDH
from typing import Tuple
import hashlib
# from ecpy.keys   import ECPublicKey, ECPrivateKey
# from ecpy.curves import Curve

curve = NIST256p

# Schnorr NIZK Proof
def schnorr_nizk_proof(sk, vk, message):
    # Step 1: Generate a random number v and compute V = vG
    v = secrets.randbelow(curve.order)  # Random scalar
    V = curve.generator * v             # R is a point on the curve

    # Step 2: Compute the challenge c = H(G || R || vk || OtherInfo)
    hasher = hashlib.sha256(curve.generator.to_bytes() + V.to_bytes() + vk.to_string() + message)
    c = int.from_bytes(hasher.digest())

    # Step 3: Compute the response r = v - c * PrK % curve_order
    r = v - (c * sk.privkey.secret_multiplier) % curve.order
    
    return V, r

# Verification function
def schnorr_nizk_verify(V, r, vk, message):
    # Step 1: Compute the challenge again
    hasher = hashlib.sha256(curve.generator.to_bytes() + V.to_bytes() + vk.to_string() + message)
    c = int.from_bytes(hasher.digest())
    
    # Step 2: Verify R' = sG + c*vk
    G = curve.generator
    rG = r * G
    c_vk = c * vk.pubkey.point
    V_prime = rG + c_vk

    return V_prime == V


# OLD
# def generate_proof(curve: Curve, prk: ECPrivateKey, PK: ECPublicKey, id: int, gid: int, data=b"sample"):
#     n = curve.order
#     G = curve.generator

#     # if (len(sys.argv)>1):
#     #     message = str(sys.argv[1])

#     M = data
    
#     v = ECPrivateKey(secrets.randbits(256), curve)  # choose v randomly
#     V = v.get_public_key()                          # V = G x v

#     c = generate_challenge(G, V, PK, id, gid, M)

#     r = (v.d - (prk.d * c)) % n                     # proof

#     return (PK, id, gid, M, V, r)

# def generate_proof_fog(curve, prk, PK, data=b"sample"):
#     n = curve.order
#     G = curve.generator

#     if (len(sys.argv)>1):
#         message = str(sys.argv[1])

#     M = data

#     v = ECPrivateKey(secrets.randbits(256), curve)  # choose v randomly
#     V = v.get_public_key()                          # V = G x v

#     c = generate_challenge_fog(G, V, PK, M)

#     r = (v.d - (prk.d * c)) % n                     # proof

#     return (PK, M, V, r)

# def generate_challenge(G, V, PK, id, gid, M):
#     hasher = hashlib.sha256((G.x).to_bytes(32)              # 256 bits
#             + (G.y).to_bytes(32)
#             + (V.W.x).to_bytes(32)
#             + (V.W.y).to_bytes(32)
#             + (PK.W.x).to_bytes(32)
#             + (PK.W.y).to_bytes(32)
#             + (id).to_bytes(32)
#             + (gid).to_bytes(32)
#             + M)

#     return int.from_bytes(hasher.digest())

# def generate_challenge_fog(G, V, PK, M):
#     hasher = hashlib.sha256((G.x).to_bytes(32)              # 256 bits
#             + (G.y).to_bytes(32)
#             + (V.W.x).to_bytes(32)
#             + (V.W.y).to_bytes(32)
#             + (PK.W.x).to_bytes(32)
#             + (PK.W.y).to_bytes(32)
#             + M)

#     return int.from_bytes(hasher.digest())

# def verify_proof(proof: Tuple[ECPublicKey, int, int, bytes, ECPublicKey, int], G) -> bool:
#   (PK, id, gid, M, V, r) = proof
#   c = generate_challenge(G, V, PK, id, gid, M)

#   v1 = V.W
#   v2 = (G * r) + (PK.W * c)
  
#   return v1==v2

# def verify_proof_fog(proof: Tuple[ECPublicKey, bytes, ECPublicKey, int], G) -> bool:
#   (PK, M, V, r) = proof
#   c = generate_challenge_fog(G, V, PK, M)

#   v1 = V.W
#   v2 = (G * r) + (PK.W * c)
  
#   return v1==v2