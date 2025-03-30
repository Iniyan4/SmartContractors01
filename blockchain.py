import hashlib
import json
import os
from time import time
from typing import Dict, Any

class Block:
    def __init__(self, index: int, timestamp: float, data: Dict[str, Any], previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self, storage_file = 'blockchain.json'):
        self.storage_file = storage_file
        self.chain = []
        self.load_from_disk() or self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, time(), {"genesis": True}, "0")
        self.chain = [genesis]
        self.save_to_disk()
        return True

    def save_to_disk(self):
        chain_data = [{
            'index': block.index,
            'timestamp': block.timestamp,
            'data': block.data,
            'previous_hash': block.previous_hash,
            'hash': block.hash
        } for block in self.chain]

        with open(self.storage_file, 'w') as f:
            json.dump(chain_data, f, indent=2)

    def add_block(self, data: Dict[str, Any]) -> None:
        previous_block = self.chain[-1]
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=time(),
            data=data,
            previous_hash=previous_block.hash
        )
        self.chain.append(new_block)

    def load_from_disk(self):
        """Load blockchain from JSON file if exists"""
        if not os.path.exists(self.storage_file):
            return False

        try:
            with open(self.storage_file, 'r') as f:
                chain_data = json.load(f)

            self.chain = [
                Block(
                    index=item['index'],
                    timestamp=item['timestamp'],
                    data=item['data'],
                    previous_hash=item['previous_hash']
                ) for item in chain_data
            ]
            return self.is_valid()
        except:
            return False
    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

    def repair_chain(self):
        """Attempt to repair corrupted blockchain"""
        backup_file = f"{self.storage_file}.bak"
        os.replace(self.storage_file, backup_file)
        self.create_genesis_block()
        return True