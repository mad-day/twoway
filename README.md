# twoway
A cryptographic scheme based on Pairing-based cryptography (bn256).

The scheme has a behavoir similar to RSA: In RSA, you can encrypt a
message with the private key, that you can only decrypt with the
public key. Furthermore, the keys look similar, as both public and
private key consist of a large modulus and an exponent. Finally, in
RSA, neighter the private key can be computed from the public key,
nor the public key can be computed from the private key.

Here are some similarities to RSA.

* The public key can't be computed from the private key
* Encryption and Decryption works in both directions.
* The owner of the private key can Encrypt messages, that can be decrypted using the public key.


