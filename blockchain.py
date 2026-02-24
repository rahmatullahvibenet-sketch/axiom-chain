import hashlib, time, json

class Block:
    def __init__(self, index, data, prev_hash):
        self.index = index
        self.time = time.time()
        self.data = data
        self.prev_hash = prev_hash
        self.hash = self.mine()
    
    def mine(self):
        content = f"{self.index}{self.time}{self.data}{self.prev_hash}"
        return hashlib.sha256(content.encode()).hexdigest()

class AxiomChain:
    def __init__(self):
        self.chain = [Block(0, "AXIOM GENESIS", "0")]
        print("AXIOM CHAIN STARTED")
    
    def add(self, data):
        prev = self.chain[-1]
        block = Block(len(self.chain), data, prev.hash)
        self.chain.append(block)
        print(f"Block {block.index} added: {block.hash[:16]}")
    
    def show(self):
        for b in self.chain:
            print(f"\nBlock {b.index}")
            print(f"Data: {b.data}")
            print(f"Hash: {b.hash[:20]}")

ax = AxiomChain()
ax.add("First Axiom Transaction")
ax.show()
