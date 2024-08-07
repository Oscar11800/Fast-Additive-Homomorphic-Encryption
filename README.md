# Fast Additive Homomorphic Encryption (FAHE) Implementation

## Overview
This repository contains the implementation of the FAHE1 and FAHE2 encryption schemes, based on the Fast Additive Partially Homomorphic Encryption from the Approximate Common Divisor Problem. These schemes enable the execution of addition operations directly on encrypted data.

This project attempts to replicate Cominetti's experiments on FAHE1 and FAHE2 with variable security parameters, message lengths, and maximum number of additions.

*Disclaimer: The FAHE1 & 2 processes described below are merely summarized in importance of our analysis from Cominetti's research and do not explain some of the math involved.*

### How to Run Homomorphic Additivity Tests
First, navigate to `/tests` folder

Changing Constants:
- Change `NUM_TRIALS` to run each test a different number of times (*Note:* This may make tests slower).
- Change `TOGGLE_FIXED_MESSAGE` for debugging. This generates message lists with only a single unique message.
- Change `FIXED_MESSAGE` to change what unique message is generated.

Running Preset Addition Tests:
- You can run all addition tests by running `python3 -m pytest -s testfahe.py`
- You can run only fahe1 addition tests by running `python3 -m pytest -s testfahe.py -m "fahe1"`
- You can run only fahe2 addition tests by running `python3 -m pytest -s testfahe.py -m "fahe2"`
- You can run only fast fahe1 addition tests by running `python3 -m pytest -s testfahe.py -m "fahe1 and not slow"`
- You can run specific tests/functions by running `python3 -m pytest -s -m testfahe.py::[class name]::[test name]`

Running Custom Tests:
- Change the custom constants as necessary
- Run custom tests by running: `python3 -m pytest -s testfahe.py -m "custom"`

Suggested Custom Experiments:
You can set your own custom experiment parameters and try running tests
- Start with $\(\lambda = 128\)$
- Test with $\(|m_{max}| = 32\)$ and $\(\alpha = 6\)$.
- Increase $\(|m_{max}|\)$ to 64 and observe the impact.
- Increment $\(\alpha\)$ gradually (e.g., $\(\alpha = 10, 15, 20, 25, 30\)$) and evaluate performance.
- If higher security is needed, test with $\(\lambda = 256\)$ 

## How to Use This Project
Clone this repository using:
```bash
git clone https://github.com/Oscar11800/Fast-Additive-Homomorphic-Encryption.git
```

Make sure to have the current requirements by installing requirements: 
```bash
pip install -r requirements.txt
```

To run the current tests, please reference the above section on running additivity tests


To run the ipynb graphing file:
- Navigate to `/legacy` folder and run:
```bash
jupyter notebook plot_performance.ipynb
```

To run csv benchmark tests, edit ```analysis.py``` with desired values and run:
- Navigate to `/legacy` folder and run:
```bash
python3 analysis.py
```
### File Structure (Current Testing Framework)
| File Name           | Description                                                                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `src/fahe.py`          | FAHE1 key generation, encryption, and decryption calculations. Used in `plot_performance.ipynb`, `data_collection.py`, and `test.py`.     |
| `tests/testfahe.py`          | Same as `fahe1.py` but for FAHE2.                                                                                                          |


### Legacy File Structure (Older Tests)
| File Name           | Description                                                                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `fahe1.py`          | FAHE1 key generation, encryption, and decryption calculations. Used in `plot_performance.ipynb`, `data_collection.py`, and `test.py`.     |
| `fahe2.py`          | Same as `fahe1.py` but for FAHE2.                                                                                                          |
| `helper.py`         | Helper functions (e.g., prime number calculation). Credit: Oded Leiba.                                                                     |
| `plot_performance.ipynb` | Matplotlib graphs of FAHE1 benchmark tests vs. λ, α, and m_max variables.                                                              |
| `data_collection.py` | Similar to `plot_performance.ipynb` but creates dictionaries for benchmark testing.                                                       |
| `plotting.py`       | Helper class for matplotlib in `test.py`.                                                                                                 |
| `test.py`           | Unit tests for FAHE1/FAHE2 functions, benchmark tests, and plotting.                                                                      |
| `analysis.py`       | USE THIS TO RUN EXPERIMENTS! CSV writing code. Edit to run csv benchmark tests with different values.                                                                 |
| `old_csv folder`         | Past (outdated) results of experiments.   |
| `experiment_params.txt`       | Contains information on parameters and machine info of the latest experiment run                                                             |
| `analysis_tests folder`       | USE THIS AFTER ANALYZING. Contains latest csvs from experiments                                                           |

## FAHE 1 & 2 Experimentation
### FAHE 1 & FAHE 2 Facts and Intuitions
- FAHE relies on symmetric keys for both encryption and decryption.
- FAHE is additively homomorphic, so addition can be performed by any entity.
- FAHE is partially and somewhat homomorphic; i.e., they only support addition a limited number of times.
- Cominetti states that with a suitable choice of parameters, the total number of additions can be "practically unlimited."
- FAHE relies on the Approximate Common Divisor (ACD) as its security problem.
- FAHE1 uses distribution of positive noise to encrypt messages.
- **Note: FAHE is unable to provide IND-CCA2 security.**

### Assumptions and Variables
| Symbol | Description                       |
| :----- | :-------------------------------- |
| $\(p\)$   | prime number of size $\(\eta\)$ bits. |
| $\(q\)$   | integer in interval $\([0, 2^{\gamma} / p]\)$. |
| $\(\gamma\)$: gamma | ciphertext's final size.         |
| $\(\rho\)$: rho  | noise size, determines $\(r)\$                       |
| $\(\eta\)$: eta  | secret key size, determines size of $\(p\)$                   |
| $\(r\)$   | random noise defined by $\(\rho\)$, determines ciphertext's final size    |
| (&alpha;): alpha | determines total number of supported additions |
| (&lambda;): lambda | security parameter (commonly 128 or 256 bits) |

If the desired security level against classical computers is $\(\lambda\)$ bits, we must have:
- $\(\rho \geq \lambda\)$
- $\(\eta > \rho\)$
- $\(\gamma \geq \Omega\left( \frac{\rho}{\log_2(\rho)} \cdot (\eta - \rho)^2 \right)\)$

### FAHE1.Keygen($\lambda$, $|m_{max}|$, $\alpha$)
1. Choose a suitable security parameter $\lambda$, the maximum message size $|m_{max}|$, and the parameter $\alpha$ that defines the total number of supported additions.
2. Compute the set of parameters $(\rho, \eta, \gamma)$:
   - $\rho = \lambda$
   - $\eta = \rho + 2\alpha + |m_{max}|$
   - $\gamma = \left(\frac{\rho}{\log \rho}\right) \cdot (\eta - \rho)^2$
3. Pick a prime $p$ of size $\eta$ and set $X = 2^{\gamma} / p$.

Set the scheme's key to $k = (\rho, |m_{max}|, X, p, \alpha)$.

- **Encryption Key (ek):** $(p, X, \rho, \alpha)$
- **Decryption Key (dk):** $(p, |m_{max}|, \rho, \alpha)$

### FAHE1.Encr($m$)
1. Given a message $m$, sample $q \leftarrow [0, X]$.
2. Generate noise $\text{noise} \leftarrow \{0, 1\}^\rho$ and compute $M = (m \ll (\rho + \alpha)) + \text{noise}$.
3. Compute $n = p \cdot q$ and output $c = n + M$.

### FAHE1.Add($c1$, $c2$)
1. Given two ciphertexts $c1$ and $c2$, output $c_{\text{add}} = c1 + c2$.

### FAHE1.Decr($c$)
1. Given the ciphertext $c$, output the least significant $|m_{max}|$ bits of:
   - $m = (c \mod p) \gg (\rho + \alpha)$

### FAHE2.Keygen($\lambda$, $|m_{max}|$, $\alpha$)
1. Choose a suitable security parameter $\lambda$, the maximum message size $|m_{max}|$, and the parameter $\alpha$ that defines the total number of supported additions.
2. Compute the set of parameters $(\rho, \eta, \gamma, p, X, \text{pos})$, given by:
   - $\rho = \lambda + \alpha + |m_{max}|$
   - $\eta = \rho + \alpha$
   - $\gamma = \left(\frac{\rho}{\log \rho}\right) \cdot (\eta - \rho)^2$
3. Pick a prime $p$ of size $\eta$ and set $X = 2^{\gamma} / p$ and $\text{pos} \leftarrow [0, \lambda]$.

Set the scheme's key to $k = (p, X, \text{pos}, |m_{max}|, \lambda, \alpha)$.

- **Encryption Key (ek):** $(p, X, \text{pos}, \rho, |m_{max}|, \lambda, \alpha)$
- **Decryption Key (dk):** $(p, \text{pos}, |m_{max}|, \alpha)$

### FAHE2.Encr($m$)
1. Given a message $m$, sample $q \leftarrow [0, X]$.
2. Generate $\text{noise1} \leftarrow \{0, 1\}^{\text{pos}}$, $\text{noise2} \leftarrow \{0, 1\}^{\lambda - \text{pos}}$, and make
   - $M = (\text{noise2} \ll (\text{pos} + |m_{max}| + \alpha)) + (m \ll (\text{pos} + \alpha)) + \text{noise1}$.
3. Compute $n = p \cdot q$ and output $c = n + M$.

### FAHE2.Add($c1$, $c2$)
1. Given two ciphertexts $c1$ and $c2$, output $c_{\text{add}} = c1 + c2$. Note that, like in FAHE1, the ciphertext size can increase during this operation due to carries.

### FAHE2.Decr($c$)
1. Given the ciphertext $c$, output the least significant $|m_{max}|$ bits of:
   - $m = (c \mod p) \gg (\text{pos} + \alpha)$

### FAHE Suggested Values
- $\(\frac{\gamma - \rho}{\eta - \rho} \geq 800\)$ is sufficient to prevent any practical lattice attack (this is achievable with a minimum $\(\alpha\)$ value).
- For FAHE1, consider a desired security level of $\(\lambda = 128\)$ against classical computers, $\(m_{max}\)$ of 32 and 64 bits. For this scenario, the author claims that $\(\alpha \geq 32\)$ for $\(\lambda = 128\)$ and $\(m_{max} = 32\)$.
- For FAHE2, when $\(\lambda = 128\)$, he recommends setting $\(\alpha \geq 32\)$ for $\(m_{max} = 64\)$.
- For FAHE1, when $\(\lambda = 256\)$, $\(\alpha \geq 6\)$.
- For FAHE2, when $\(\lambda = 256\)$, $\(\alpha \geq 22\)$ for $\(m_{max} = 32\)$ and $\(\alpha \geq 21\)$ for $\(m_{max} = 64\)$.
- Some scenarios may desire a larger $\(\alpha\)$ ie. more data to add.
- Set $\(\lambda\)$ to 256 for post-quantum secure implementation and 128 for classical computers.        

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
	Paillier can perform unlimited # of additions, FAHE can perform $2^\(alpha - 1\)$ additions
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

References:
E. L. Cominetti and M. A. Simplicio, "Fast Additive Partially Homomorphic Encryption From the Approximate Common Divisor Problem," in IEEE Transactions on Information Forensics and Security, vol. 15, pp. 2988-2998, 2020, doi: 10.1109/TIFS.2020.2981239.
Abstract: This paper presents two efficient partially homomorphic encryption schemes built upon the approximate common divisor problem, believed to be resistant to quantum computer attacks. Both proposals, named FAHE1 and FAHE2, are additively homomorphic and have a symmetric nature, meaning that they are useful in scenarios where encryption and decryption are performed by the same entity. This is the case, for example, of encrypted databases stored in a public cloud. We also evaluate the performance of our proposals in comparison with two alternatives displaying additive homomorphism: the traditional Paillier asymmetric cryptosystem, which is not quantum-resistant; and the XPIR algorithm, which is both quantum-resistant and symmetric. Our experimental results show that both solutions provide considerable speed-ups when compared to Paillier. Namely, encryption and decryption with FAHE1 are, respectively, 120 and 25 times faster than Paillier's, while for FAHE2 both operations run more than 1000 times faster. In addition, when compared with a highly optimized XPIR code, our reference implementation remains quite competitive while producing smaller ciphertexts.
keywords: {Encryption;Additives;Proposals;Databases;Cloud computing;Partially homomorphic encryption;approximate common divisor;addition;fast;Paillier},
URL: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9057655&isnumber=8833568



