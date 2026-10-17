# Volatility plugin that checks, inside the frozen executable, the native code
# that Volatility loads only when a plugin needs it: distorm3 (malfind), yara
# (yarascan) and the Crypto ciphers and hashes (hashdump, lsadump, cachedump).
# ct/smoke_test.py runs it with --plugins. It is not part of the release.
#
# Licensed under the GNU General Public License, version 2 or later, the same
# as Volatility.

import binascii

import volatility.commands as commands


def _hex(data):
    return binascii.hexlify(data).decode("ascii")


class CTSelfTest(commands.Command):
    """Checks the bundled distorm3, yara and Crypto with known answers"""

    def calculate(self):
        import distorm3
        decoded = [i[2] for i in distorm3.Decode(0, "\x55\x89\xe5\xc3", distorm3.Decode32Bits)]
        yield "distorm3", decoded == ["PUSH EBP", "MOV EBP, ESP", "RET"], repr(decoded)

        import yara
        rules = yara.compile(source='rule ct_selftest { strings: $a = "VOLATILITY" condition: $a }')
        matched = [m.rule for m in rules.match(data="..VOLATILITY..")]
        yield "yara", matched == ["ct_selftest"], "yara-python {0}, matched {1}".format(yara.__version__, matched)
        # The modules the Windows yara-python wheel has; Cyber Triage passes users' rules to yarascan.
        for module in ("pe", "elf", "math", "hash", "dotnet", "cuckoo", "time"):
            try:
                yara.compile(source='import "{0}" rule ct_{0} {{ condition: true }}'.format(module))
                yield "yara module " + module, True, "compiles"
            except yara.SyntaxError as error:
                yield "yara module " + module, False, str(error)

        from Crypto.Cipher import AES, ARC4, DES
        from Crypto.Hash import HMAC, MD4, MD5, SHA256
        # RFC 1320, RFC 1321 and FIPS 180-2 test vectors.
        yield "MD4", MD4.new("abc").hexdigest() == "a448017aaf21d8525fc10ae87aa6729d", MD4.new("abc").hexdigest()
        yield "MD5", MD5.new("abc").hexdigest() == "900150983cd24fb0d6963f7d28e17f72", MD5.new("abc").hexdigest()
        digest = SHA256.new("abc").hexdigest()
        yield "SHA256", digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest
        # RFC 2104. cachedump calls HMAC.new without a digest module, which means MD5.
        digest = HMAC.new("Jefe", "what do ya want for nothing?").hexdigest()
        yield "HMAC-MD5", digest == "750c783e6ab0b503eaa86e310a5db738", digest
        # The classic DES worked example, as hashdump calls it.
        block = DES.new(binascii.unhexlify("133457799bbcdff1"), DES.MODE_ECB).encrypt(binascii.unhexlify("0123456789abcdef"))
        yield "DES", _hex(block) == "85e813540f0ab405", _hex(block)
        stream = ARC4.new("Key").encrypt("Plaintext")
        yield "ARC4", _hex(stream) == "bbf316e8d940af0ad3", _hex(stream)
        # FIPS-197 AES-128, decrypted in CBC mode with a zero IV, as lsadump calls it.
        plain = AES.new(binascii.unhexlify("000102030405060708090a0b0c0d0e0f"), AES.MODE_CBC, "\x00" * 16).decrypt(
            binascii.unhexlify("69c4e0d86a7b0430d8cdb78070b4c55a"))
        yield "AES", _hex(plain) == "00112233445566778899aabbccddeeff", _hex(plain)

    def render_text(self, outfd, data):
        for name, ok, detail in data:
            outfd.write("{0}: {1} ({2})\n".format(name, "ok" if ok else "FAIL", detail))
