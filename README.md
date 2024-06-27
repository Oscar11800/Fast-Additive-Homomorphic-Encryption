# Fast Additive Homomorphic Encryption (FAHE) Implementation

## Overview
This repository contains the implementation of the FAHE1 and FAHE2 encryption schemes, based on the Fast Additive Partially Homomorphic Encryption from the Approximate Common Divisor Problem. These schemes enable the execution of addition operations directly on encrypted data.

## FAQ
- What are homomorphic encryption schemes? Privacy homomorphisms are encryption methods that allow operations on encrypted data without decryption
	"This homomorphism property is remarkably valuable when the computation is performed by a third party that 
	is not fully trusted, which is the case of databases stored in a public cloud environment. In such scenarios,
	homomorphic schemes enable data storage and processing without risking information exposure so users can 
	benefit from the cloud's potential cost reductions without compromising their security."

- Why are we interested in homomorphic encryption? Because we are concerned about privacy and security when it comes 
	to cloud computing. FAHE1 and 2 may be useful with encrypted cloud database frameworks ie. CryptDB. This is because users in CryptDB communicates with cloud database with a single proxy responsible for all encryption & decryption, thus an asymmetric scheme (ie. Paillier) is not required
thus it can take advantage of the performance gains of FAHE 1 & 2

- What is the problem with homomorphic encryption? Homomorphic encryptions tend to be computationally intensive which is why partially homomorphic encryptions may be chosen over fully homomorphic encryptions

- XPIR vs. FAHE1 & FAHE2:
	FAHE1 with small parameters and FAHE2 with large parameters are competitive with XPIR
	XPIR uses optimized LWE (learning with errors) library whereas FAHE 1 & 2 use standard cryptography libraries which means FAHE can be further optimized
	FAHE1 & 2 produce less cyphertext than XPIR (XPIR creates 7-8x more cyphertext)

- Paillier vs FAHE1 & FAHE2:
	FAHE1 20x faster @ keygen, 120x faster @ encrypt, 25x faster @ decrypt, 8x faster @ homomorphic operation, 50x more cyphertext 
	FAHE2 95x faster @ keygen, 1200x faster @ encrypt, 1300x faster @ decrypt, 90x faster @ homomorphic operation, 5x more cyphertext
	Paillier can perform unlimited # of additions, FAHE can perform 2^(alpha - 1) additions
	Paillier is asymmetric, FAHE is symmetric

- How is FAHE1 different than FAHE2?
	FAHE1 is 100x faster at encryption and 25x faster at decrypt. than Paillier whereas FAHE2 is 1000x faster for both.
	What is FAHE1: FAHE1 is simple application of approximate common divisor problem.
	What is FAHE2: FAHE2 is slightly modified FAHE1 with shorter ciphertexts but based on stronger security assumptions.

- What does it mean for an encryption to be partially homomorphic? The encryption is homomorphic for specific operations.

- What does it mean for an encryption to be somewhat homomorphic? The encryption is homomorphic for multiple operations, but only a limited number of times

- What does it mean for an encryption to be Fully homomorphic?
	The encryption is homomorphic for multiple operations an unlimited # of times
	Any alg. can be executed without breaking privacy breach
	Downside: it's more computationally intensive than partially or somewhat homomorphic


## Features
- **FAHE1 and FAHE2**: Two distinct homomorphic encryption schemes.
- **Optimized Performance**: Faster than traditional systems like Paillier for certain operations.
- **Quantum Resistance**: Designed to be secure against potential quantum computer attacks.

## Installation
Clone this repository using:
```bash
git clone https://github.com/Oscar11800/Fast-Additive-Homomorphic-Encryption.git
cd Fast-Additive-Homomorphic-Encryption
```

   FAHE1 and FAHE2 Implementation: Provides two distinct encryption schemes built on the Approximate Common Divisor problem, noted for its resistance to quantum computer attacks.
   Performance Optimization: Both schemes are optimized for fast encryption, decryption, and additive operations compared to traditional systems like Paillier.
   Security: Leverages properties that are believed to be secure against both classical and quantum computational attacks.

References:
Cominetti, Eduardo & Simplicio, Marcos. (2020). Fast Additive Partially Homomorphic Encryption From the Approximate Common Divisor Problem. IEEE Transactions on Information Forensics and Security. DOI: 10.1109/TIFS.2020.2981239.
