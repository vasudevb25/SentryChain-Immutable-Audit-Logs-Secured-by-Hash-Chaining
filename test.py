from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
# load public key
with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# use SAME payload string
payload_string = json.dumps(evidence["payload"], sort_keys=True)

public_key.verify(
    bytes.fromhex(evidence["signature"]),
    payload_string.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("VALID")