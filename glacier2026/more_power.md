# More Power

**Category:** Cryptography

## Challenge Overview

In this challenge, we're given an RSA service where we can choose both the message to encrypt and the public exponent `e`, as long as `e > 65537`.

We can also request the encrypted flag by sending a JSON payload without the `msg` field.

The problem is that we don't know the modulus `n`, only that the primes `p` and `q` remain fixed throughout the session.

Our approach was to:

1. Recover `n` using messages of our choice.
2. Request the encrypted flag twice, using different exponents.
3. Recover the flag using a **Common Modulus Attack**.

## 1. Recovering the Modulus

We know that RSA encryption works as follows:

\[
c=m^e\bmod n
\]

This means that:

\[
m^e-c=k\cdot n
\]

For some integer \(k\). In other words, **the difference between \(m^e\) and the ciphertext is a multiple of \(n\)**.

Since we can encrypt messages of our choice, we can obtain several of these multiples and calculate their GCD to recover the modulus.

For this, we chose:

```python
e1 = 65539

m1 = "1"
m2 = "2"
m3 = "3"
```

One important detail is that the messages are strings, so we need to convert them to their integer representation using `bytes_to_long()`. For example, `"1"` corresponds to `49`, not `1`.

After receiving the three ciphertexts, we calculate:

\[
n\mid\gcd(m_1^e-c_1,\ m_2^e-c_2,\ m_3^e-c_3)
\]

The GCD may initially return a multiple of the modulus, but using multiple messages increases the chances of obtaining exactly `n`.

Our implementation:

```python
def get_n():
    plaintexts = [m1, m2, m3]
    differences = []

    for m, c in zip(plaintexts, messages):
        m_int = bytes_to_long(m.encode())
        differences.append(pow(m_int, e1) - c)

    n = 0

    for diff in differences:
        n = gcd(n, diff)

    return abs(n)
```

With this, we managed to recover the modulus without knowing either `p` or `q`.

## 2. Common Modulus Attack

Now that we have `n`, we can move on to the actual flag.

The idea behind the [RSA Common Modulus Attack](https://blog.0daylabs.com/2015/01/17/rsa-common-modulus-attack-extended-euclidean-algorithm/) is that, if the same message is encrypted using the same modulus but two different coprime public exponents, we can recover the plaintext without the private key.

We chose:

```python
e1 = 65539
e2 = 65543
```

These exponents satisfy the challenge's requirements, and more importantly:

\[
\gcd(e_1,e_2)=1
\]

We then requested the encrypted flag twice:

```python
payload_flag1 = prepare_payload_flag(e1)
payload_flag2 = prepare_payload_flag(e2)

c1 = recover_message_flag(r, payload_flag1)
c2 = recover_message_flag(r, payload_flag2)
```

This gives us:

\[
c_1=m^{e_1}\bmod n
\]

\[
c_2=m^{e_2}\bmod n
\]

Where `m` is the flag we're trying to recover.

### Finding a and b — Extended Euclidean Algorithm

To combine both ciphertexts, we first need to find two integers `a` and `b` such that:

\[
ae_1+be_2=1
\]

This comes from **Bézout's identity**, which states that for any two integers \(x,y\), there exist integers \(a,b\) satisfying:

\[
ax+by=\gcd(x,y)
\]

Since our exponents are coprime, their GCD is `1`.

We can calculate these coefficients using the [Extended Euclidean Algorithm](https://cp-algorithms.com/algebra/extended-euclid-algorithm.html), which extends the regular Euclidean algorithm to return these coefficients alongside the GCD.

Our implementation:

```python
def egcd(a, b):
    if b == 0:
        return a, 1, 0

    g, x, y = egcd(b, a % b)

    return g, y, x - (a // b) * y
```

Running:

```python
_, a, b = egcd(e1, e2)
```

Gives:

```text
a = -16386
b = 16385
```

Which satisfies:

\[
(-16386)(65539)+(16385)(65543)=1
\]

Now we can use these coefficients to recover the original message.

### Combining the Ciphertexts

Remember that:

\[
c_1=m^{e_1}\bmod n
\]

\[
c_2=m^{e_2}\bmod n
\]

If we raise each ciphertext to its corresponding coefficient and multiply them:

\[
c_1^ac_2^b\equiv m^{ae_1+be_2}\pmod n
\]

And since we already know that:

\[
ae_1+be_2=1
\]

We get:

\[
\boxed{m=c_1^ac_2^b\bmod n}
\]

So, theoretically, we've already recovered the flag. There's just one small issue: **one of our exponents is negative**.

### Handling Negative Exponents

In our case:

\[
a=-16386
\]

To deal with negative exponents in modular arithmetic, we use the **modular multiplicative inverse**.

As explained in [CP-Algorithms — Modular Multiplicative Inverse](https://cp-algorithms.com/algebra/module-inverse.html), the modular inverse of an integer \(x\) is a value \(x^{-1}\) such that:

\[
x\cdot x^{-1}\equiv1\pmod n
\]

This inverse exists if:

\[
\gcd(x,n)=1
\]

A negative exponent can then be rewritten as:

\[
x^{-k}\equiv(x^{-1})^k\pmod n
\]

So instead of trying to directly calculate \(c_1^{-16386}\), we first calculate its modular inverse and then raise it to `16386`.

We implemented this with:

```python
def signed_pow(c, exponent, n):
    if exponent < 0:
        return pow(inverse(c, n), -exponent, n)

    return pow(c, exponent, n)
```

The `inverse()` function from PyCryptodome handles the modular inverse calculation for us.

Finally, we can recover the original message:

```python
_, a, b = egcd(e1, e2)

m = signed_pow(c1, a, n) * signed_pow(c2, b, n) % n

print(long_to_bytes(m))
```

The final `long_to_bytes()` converts the recovered integer back into bytes, revealing the flag.

## Conclusion

The challenge was solved without factoring the modulus or calculating the private key.

First, we used the chosen-plaintext functionality to recover the hidden modulus by computing the GCD of several values of \(m^e-c\).

Then, since the service allowed us to request the same flag encrypted under two different coprime public exponents, we applied the **Common Modulus Attack**.

Using the Extended Euclidean Algorithm, we found coefficients that allowed us to combine both ciphertexts and recover the original plaintext.

The main weakness was the combination of **textbook RSA, a fixed modulus, and user-controlled public exponents**. Hiding `n` wasn't enough to prevent the attack.
