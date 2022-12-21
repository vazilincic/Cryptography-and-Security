# CRYPTOGRAPHY AND SECURITY LABORATORY WORK 4

## HOW TO RUN

```bash
python run.py -s "hello world"
```

## TOPIC: HASH FUNCTIONS AND DIGITAL SIGNATURES

Hashing is a technique used to compute a new representation of an existing value, message or any piece of text. The new representation is also commonly called a digest of the initial text, and it is a one way function meaning that it should be impossible to retrieve the initial content from the digest.

Such a technique has the following usages:

- Offering confidentiality when storing passwords,
- Checking for integrity for some downloaded files or content,
- Creation of digital signatures, which provides integrity and non-repudiation.

In order to create digital signatures, the initial message or text needs to be hashed to get the digest. After that, the digest is to be encrypted using a public key encryption cipher. Having this, the obtained digital signature can be decrypted with the public key and the hash can be compared with an additional hash computed from the received message to check the integrity of it.

## OBJECTIVES

1. Get familiar with the hashing techniques/algorithms.
2. Use an appropriate hashing algorithms to store passwords in a local DB.
    - You can use already implemented algortihms from libraries provided for your language.
    - The DB choise is up to you, but it can be something simple, like an in memory one.
3. Use an asymmetric cipher to implement a digital signature process for a user message.
    - Take the user input message.
    - Preprocess the message, if needed.
    - Get a digest of it via hashing.
    - Encrypt it with the chosen cipher.
    - Perform a digital signature check by comparing the hash of the message with the decrypted one.

## THE SHA256 ALGORITHM

In Cryptography, SHA is cryptographic hash function which takes input as 20 Bytes and rendered the hash value in hexadecimal number, 40 digits long approx.

## IMPLEMENTATION

Initialize hash values.

```python
self.hashes = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
]
```

Initialize array of round constants.

```python
self.constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
```

_Pre-processing (Padding):_

begin with the original message of length L bits
append a single '1' bit
append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> , (the number of bits will be a multiple of 512)

Process the message in successive 512-bit chunks:

```python
# Convert the blocks into lists of 64 byte integers.
for block in self.blocks:
    # Copy block into first 16 words w[0..15] of the message schedule array.
    words = list(struct.unpack(">16L", block))
            
    # The initial values in w[0..63] don't matter, so many implementations zero them here.
    words += [0] * 48

    # Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    for i in range(16, 64):
        s0 = (
            self.right_rotate(words[i - 15], 7) ^ self.right_rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)
        )

        s1 = (
            self.right_rotate(words[i - 2], 17) ^ self.right_rotate(words[i - 2], 19) (words[i - 2] >> 10)
        )

        words[i] = (words[i - 16] + s0 + words[i - 7] + s1) % 0x100000000
```

Initialize working variables to current hash value.

```python
a, b, c, d, e, f, g, h = self.hashes
```

Compression function main loop:

```python
for index in range(0, 64):
    s1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
    ch = (e & f) ^ ((~e & (0xFFFFFFFF)) & g)
    temp1 = (
        h + s1 + ch + self.constants[index] + words[index]
    ) % 0x100000000
    s0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    temp2 = (s0 + maj) % 0x100000000

    h = g
    g = f
    f = e
    e = ((d + temp1) % 0x100000000)
    d = c
    c = b
    b = a
    a = ((temp1 + temp2) % 0x100000000)
```

Produce the final hash value (big-endian):

```python
self.hashes = [
    ((element + mutated_hash_values[index]) % 0x100000000)
    for index, element in enumerate(self.hashes)
]
```
    
### HASH RESULTS

```md
Input : hello world
Output: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

Input : GeeksForGeeks
Output: 112e476505aab51b05aeb2246c02a11df03e1187e886f7c55d4e9935c290ade

Input : K1t4fo0V
Output: 0a979e43f4874eb24b740c0157994e34636eed0425688161cc58e8b26b1dcf4e
```
    
## PROJECT WORKFLOW
    
First, let's take the user's input and parse it:
    
```py
 def take_input():
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "-s",
            "--string",
            dest="input_string",
            default="Hello World!! Welcome to Cryptography",
            help="Hash the string",
        )

        parser.add_argument(
            "-f",
            "--file",
            dest="input_file",
            help="Hash contents of a file"
        )

        args = parser.parse_args()
        input_string = args.input_string

        # hash input should be a bytestring
        if args.input_file:
            with open(args.input_file, "rb") as f:
                hash_input = f.read()
        else:
            hash_input = bytes(input_string, "utf-8")

        return hash_input
```
    
Now, let's get a digest of it via the hash I implemented:
    
```py
# Get a digest of it via hashing.
hashed_input = SHA256(msg).hash
```
    
My chosen cipher is RSA, and in my `DigitalSignature` object I have two functions for encryption and decryption.
    
```py
    @staticmethod
    def assymetric_encryption(msg):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        encrypted = public_key.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted, private_key

    @staticmethod
    def assymetric_decryption(encrypted_message, private_key):
        original_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return original_message
```
   
The last step is to create a function to perform the digital signature check.
    
```py
    @staticmethod
    def digital_signature_check(original_message, decrypted_message):
        if SHA256(original_message).hash == decrypted_message:
            print("STATUS: OK. HASHES ARE THE SAME")
```
 
And let's save all the hashes in a local hash map.
    
```py
    @staticmethod
    def save_to_datastore(key, input_string):
        dummy_datastore[key] = SHA256(input_string).hash
```
  
## RESULTS / CONCLUSION
    
During this laboratory work we implemented a `Digital Signature Check` for a user input with a `Hashing Algorithm`. The tools I implemented and used are `SHA256` and `RSA Cipher`. In the end, I performed a digital signature check by comparing the hash of the message with the decrypted one. The main code and results are as follow:
    
```py
if __name__ == '__main__':
    # Take the user input message.
    msg = DigitalSignature.take_input()

    # Get a digest of it via hashing.
    hashed_input = SHA256(msg).hash

    print(hashed_input)

    # Encrypted message.
    encrypted_message, private_key = DigitalSignature.assymetric_encryption(
        hashed_input.encode())
    
    # Decrypted message.
    decrypted_message = DigitalSignature.assymetric_decryption(
        encrypted_message, private_key).decode()

    # Perform a digital signature check by comparing the hash of the message with the decrypted one.
    DigitalSignature.digital_signature_check(msg, decrypted_message)
```
    
Output:
    
```md
STATUS: OK. HASHES ARE THE SAME
```
