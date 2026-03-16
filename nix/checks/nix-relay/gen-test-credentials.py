"""Generate JWKS and JWT token from test RSA keys for NixOS VM tests."""

import base64
import json
import os
import sys

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

private_key_path = sys.argv[1]
public_key_path = sys.argv[2]
out_dir = sys.argv[3]

with open(private_key_path) as f:
    private_pem = f.read()

with open(public_key_path) as f:
    public_pem = f.read()

pub_key = load_pem_public_key(public_pem.encode())
numbers = pub_key.public_numbers()


def int_to_b64url(n: int, length: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


jwks = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-kid",
            "n": int_to_b64url(numbers.n, 256),
            "e": int_to_b64url(numbers.e, 3),
            "alg": "RS256",
            "use": "sig",
        }
    ]
}

token = jwt.encode(
    {
        "iss": "http://localhost:9999",
        "aud": "api://nix-relay",
        "exp": 9999999999,
        "repository_owner": "testorg",
        "repository": "testorg/testrepo",
    },
    private_pem,
    algorithm="RS256",
    headers={"kid": "test-kid"},
)

os.makedirs(out_dir, exist_ok=True)

with open(f"{out_dir}/jwks.json", "w") as f:
    json.dump(jwks, f)

with open(f"{out_dir}/discovery.json", "w") as f:
    json.dump({"jwks_uri": "http://localhost:9999/jwks"}, f)

with open(f"{out_dir}/token", "w") as f:
    f.write(token)
