# Ed25519-BIP32
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) defines a procedure for deriving ec-keypairs from parent keys. For ed25519 keypairs, we found this work [Ed25519-BIP](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf) to be the most promissing.

The definition of bit and byte strings as used here is found in [strings expressions](./conv-ser-enc.md).

## Little Endianness
For EdDSA and the corresponding ed-BIP32 key derivation process, all bytes to number encodings and decodings are performed assuming the __little endian__ oder of the underlying octet string.

Nevertheless, we will still be explicitly indicating it using e.g. $a_{<(le:o):32>}$ to indicate the scalar number $s$ as being from a $32$ bytes litle endian string. 

## Producing an ed25519 Extended Master Key
Following steps produce a key for use with ed255519:
- Generate a random secret seed $s_{<(b):256>}$ for the user, this shall be sufficiently random,
- normalize the random bit string $s$, computing $k_{<(b):512>} = sha512(FLAG_{<(b):?>} || s_{<(b):256>})$. Adding domain flags will keep different specification of EdDSA separated for the same secret input string $s$.
- If $k_{<(b):512:[250]>}\ne0_{<(b):1>}$, then discard $s_{<(b):256>}$, and generate a new random secret,
  - This is the $3d$ highest bit of the last byte.
  - The purpose of this operation is to keep the root private key small enougth $a \lt 2^{254} -8k_L$, with $k_L \lt 2^{250}$, such that derived private key will all be in range as compatible ed25519 private keys. See original paper at [Ed25519-BIP](https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf) for more detail.
  - If we are not generating $s$, but using a commonly defined seed, we can set $k_{<(b):512:[250]>}=0_{<(b):1>}$, to achieve the same result (todo: verify).
- set $k_{<(b):512:[0:2]>}=0_{<(b):[0:2]>}$, clearing first 3 lower bits of $k_L = k_{<b:512:[:255]>}$
  - This ensure as per curve25519 that the private key is allways a factor of 8. $c = log_2(8) = 3$.
  - $8$ being the cofactor of the curve, means the number of the points on the curve is $8p$, where p is the order of the generator $G$, we have to reject all points of order $\le 8$ to [prevent some attacks](https://crypto.stackexchange.com/questions/12425/why-are-the-lower-3-bits-of-curve25519-ed25519-secret-keys-cleared-during-creati).
- set $k_{<(b):512:[255]>}=0_{<(b):1>}$, clearing the last bit of $k_L$
  - $n = 254$. Starting with $2^{254}$, we set the lower bound of the secret scalar and clear the high order bit at $255$.
- set $k_{<(b):512:[254]>}=1_{<(b):1>}$, setting the second highest bit of $k_L$
  - this secures all secret scalars are $255$ bits. Defined for performance reasons. See [performance paper](https://www.iacr.org/cryptodb/archive/2006/PKC/3351/3351.pdf).
- compute the private key scalar $a_{<(le:o):32>} = k_{<(b):512:[:255]>} \equiv k_L$,
- compute the random scalar $r_{<(le:o):32>} = k_{<(b):512:[256:]>} \equiv k_R$,
- compute the root chaincode $c_{<(le:o):32>} = sha256(\text{0x01}_{<(o):1>}||s)$,

The resulting extended private key is the tuple $(a, r, c) = (k_L, k_R, c)$,
- Per convention, we also call this tuple $(a_{parent},r_{parrent},c_{parrent})$
- compute the public key $A_{parent} = a_{parent}G$,

## Hardened Child Key Derivation
Extended private key for child $i$ is the tuple $(a_{child:i},r_{child:i},c_{child:i}) = (k_{L:i}, k_{R:i}, c_i)$ produced as follows:

Let $HM_{<(b):512>}(key,value)$ be the function HMAC-SHA512 hash, always using the chain code as the key,

For hardened derivation, meaning $i \ge 2^{31}$, we proceed with

$$
\begin{aligned}
z_{h<(b):512>} &= HM_{<(b):512>}(c_{parent<(le:o):32>}, \text{0x00}_{<(o):1>} || a_{parent<(le:o):32>} || r_{parent<(le:o):32>} || i_{child<(le:o):4>})
\\
c'_{child:i<(b):512>} &= HM_{<(b):512>}(c_{parent<(le:o):32>}, \text{0x01}_{<(o):1>} || a_{parent<(le:o):32>} || r_{parent<(le:o):32>} || i_{child<(le:o):4>})
\\
c_{child:i<(le:o):32>} &=c'_{child:i<(b):512:[256:]>}
\end{aligned}
$$

Constructing the child key:
- $z_{hL<(le:o):28>} = z_{h<(o):64:[:27]>}$, we take the first $28$ octets of $z_h$,
- $z_{hR<(le:o):32>} = z_{h<(o):64:[32:]>}$, we take the last $32$ octets of $z_h$,
- $a_{child:i} = (8 \times z_{hL}) + a_{parent}$
- $r_{child:i} = z_{hR} + r_{parent } \pmod {2^{256}}$
- $A_{child:i} = a_{child:i}G$

The resulting extended key for child $i$ is the tuple: $(a_{child:i},r_{child:i},c_{child:i})$

### Output Validation
In case :
- $a_{child:i}$ is divisible by $|G|$, or
- $A_{child:i} = O \equiv (0, 1) \text{ identity element}$

the resulting key is invalid, and one should proceed with the next value for $i_{child}$.

## Neutered Child Key Derivation
For neutered key derivation, means $i \le 2^{31}$, we proceed with

$$
\begin{aligned}
z_{n<(b):512>} &= HM_{<(b):512>}(c_{parent<(le:o):32>}, \text{0x02}_{<(o):1>} || A_{parent<(ed:b):256>} || i_{child:<(le:o):4>})
\\
c'_{child:i<(b):512>} &= HM_{<(b):512>}(c_{parent<(le:o):32>}, \text{0x03}_{<(o):1>} || A_{parent<(ed:b):256>} || i_{child<(le:o):4>})
\\
c_{child:i<(le:o):32>} &=c'_{child:i<(b):512:[256:]>}
\end{aligned}
$$

Remark:
- $A_{<(ed:b):256>}$ is the ed25519 encoding of the public key point $A$.
- $c'_{child:i<(b):512:[256:]>}$ means the hash result for chain codes are truncated to the right 256 bits.

Constructing the child key:
- $z_{nL<(le:o):28>} = z_{n<(o):64:[:27]>}$, we take the first $28$ octets of $z_n$,
- $z_{nR<(le:o):32>} = z_{n<(o):64:[32:]>}$, we take the last $32$ octets of $z_n$,
- $a_{child:i} = (8 \times z_{nL}) + a_{parent}$
- $r_{child:i} = z_{nR} + r_{parent} \pmod {2^{256}}$
- $A_{child:i} = a_{child:i}G$, if $a_{child:i}$ available, or
- $A_{child:i} = A_{parent} \circ (8 \times z_{nL})G$

The resulting extended key for child $i$ is the tuple: $(a_{child:i},r_{child:i},c_{child:i})$

### Output Validation
In case :
- $a_{child:i}$ is divisible by $|G|$, or
- $A_{child:i} = O \equiv (0, 1) \text{ identity element}$

the resulting key is invalid, and one should proceed with the next value for $i_{child}$.

# Security Properties
We are not aware of any formal security analysis of this scheme.