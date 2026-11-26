# Flag Checker

## 1st impressions

I started this challenge by trying a bunch of different inputs, hoping to figure out how the binary validated the flag. Obviously, that wasn't getting me anywhere.
Eventually, I decided to open the binary in **Ghidra** and take a look at the decompiled code.
While exploring the binary, I noticed a label called `flags`. Naturally, I hovered over it to see what was inside.
And that's where I made a pretty stupid rookie mistake.

Ghidra's tooltip only showed a small portion of its contents, which looked like a tiny array of random values. I assumed it was just some random data used by the validation algorithm and moved on.
Well, that was literally the most important part of the challenge.

The `flags` label actually pointed to a massive array containing the encoded data we needed. The tooltip was just showing a tiny preview, and I had completely underestimated its size.

## Understanding how it works

After going back to the decompiled code and paying more attention to how `flags` was used, a few things became obvious.
First, the program reads our input and XORs each character with `0x12` and stores it on a second buffer, like this:

```c
second_buf[i] = input[i] ^ 0x12;
```

Then, there's a nested loop responsible for validating the input.

The outer loop iterates 1337 times, while the inner loop can iterate through 256 elements.
The interesting part is how the program indexes the `flags` array:

```c
flags[k + j * 256]
```

Essentially, the binary treats `flags` as a two-dimensional array, even though it's stored as a continuous block of memory.

Each row contains 256 values, and there are 1337 rows in total, since each value is a 32-bit integer, that gives us:

```text
1337 × 256 = 342272 integers
342272 × 4 = 1369088 bytes
```

That's quite a bit more data than what Ghidra's tooltip initially suggested.
The validation logic also uses XOR:

```c
cond_var ^= flags[k + j * 256] ^ second_buf[k];
```

At this point, the important observation was that the program was comparing our XOR-transformed input against values already stored inside the executable.

Which raised an obvious question:

**Why bother guessing inputs when we can just extract those values and reverse the transformation?**

## Crafting the script

### Extracting the data

Since the binary contains a symbol named `flags`, we can use `pwntools` to locate it directly, no need to execute the binary or interact with its input mechanism.
We now have the entire array in memory and can start decoding it.

### Reversing the XOR

The program transforms our input using XOR with `0x12`. The XOR operation has commutability so:

```text
(a ^ b) ^ b = a
```

So, to recover the original character from a stored value, we just apply the same XOR operation again:

```python
original = value ^ 0x12
```

Because the array contains 32-bit integers, we also need to read each element as an unsigned 32-bit value.
That's where `pwntools`' `u32()` comes in.

```python
for j in range(imax):
    decoded = bytearray()

    for k in range(jmax):
        offset = (j * jmax + k) * 4

        value = u32(raw[offset : offset + 4])
        original = value ^ 0x12
```

Essentially, we are going through every row and reconstructing the characters stored inside it.

### Regex

After running this script I was met with lot's of output, maybe the flag could be there, so to make things
cleaner, I just used regex knowing that the flag looks something like : `gctf{.*}`.

```python
match = re.search(rb"gctf\{[^}]*\}", decoded)

if match:
    print(f"flag: {match.group().decode()}")
    break
```

If we find a match, we print it and stop searching.

## Conclusion

This challenge was quite fun, and definetly not the hardest challenge ever, however it took me way too long until I realised that the `flag` symbol
was that big.
