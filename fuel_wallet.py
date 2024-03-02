from hashlib import sha256
from bip_utils import Bip39SeedGenerator
from bip_utils import Bip32Secp256k1
from bech32m import encode

    
class FuelWallet():
    
    def __init__(self, mnemonic, password='', wallet_index=0) -> None:
        
        self.mnemonic = mnemonic.strip()
        self.password = password # if have password
        self.derive_default_path = f"m/44'/1179993420'/{wallet_index}'/0/0"
        self.prefix = 'fuel'

    def get_address_pk(self):
        seed_bytes = Bip39SeedGenerator(self.mnemonic).Generate(self.password)
        bip32_mst_ctx = Bip32Secp256k1.FromSeed(seed_bytes)
        bip32_der_ctx = bip32_mst_ctx.DerivePath(self.derive_default_path)
        
        pk: bytes = bip32_der_ctx.PrivateKey().Raw().ToBytes()
        extended_key = Bip32Secp256k1.FromPrivateKey(pk)
        pubkey = extended_key.PublicKey().RawUncompressed().ToBytes().hex()[2:]
        pubkey_bytes = bytes.fromhex(pubkey)
        sha256_bytes = sha256(pubkey_bytes).digest()
        address = encode(self.prefix, sha256_bytes)

        return pk.hex(), address
       
    
       
if __name__ == '__main__':
   
    mnemonic = 'seek clean tell token spread parrot pear tray beef desk sponsor plate'
    
    for wallet_index in range(5):
        fl = FuelWallet(mnemonic=mnemonic, wallet_index=wallet_index)

        pk, address = fl.get_address_pk()
        print(f'address: {address}, pk: 0x{pk}')
    