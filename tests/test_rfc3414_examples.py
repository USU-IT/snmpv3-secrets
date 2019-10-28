from snmpv3_secrets import (
    derive_intermediate_key,
    localize_intermediate_key,
    snmpv3_key_from_password,
)

import unittest


class SNMPv3KeyDerivationTests(unittest.TestCase):
    default_test = {
        # all strings, by design
        "hmac": "md5",
        "password": "default_test",
        "intermediate_key": "019f151cd038d7e1dc297ce0f4e65ccd",
        "engineid": "00 00 00 00 00 00 00 00 00 00 00 02",
        "localized_key": "c98c55df0f118031a43f1901e0abc28a",
    }

    def test_engineid_string_input(self):
        localized_key = snmpv3_key_from_password(
            hash_type=self.default_test["hmac"],
            password=self.default_test["password"],
            engineid=self.default_test["engineid"],
        )

        self.assertEqual(self.default_test["localized_key"], localized_key)

    def test_engineid_bytes_input(self):
        localized_key = snmpv3_key_from_password(
            hash_type=self.default_test["hmac"],
            password=self.default_test["password"],
            engineid=bytes.fromhex(self.default_test["engineid"]),
        )

        self.assertEqual(self.default_test["localized_key"], localized_key)

    def test_RFC3141_MD5(self):
        # Test data from RFC3141 section A.3.1
        self.run_test(
            hmac="md5",
            password="maplesyrup",
            intermediate_key="9f af 32 83 88 4e 92 83 4e bc 98 47 d8 ed d9 63",
            engineid="00 00 00 00 00 00 00 00 00 00 00 02",
            localized_key="52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b",
        )

    def test_RFC3141_SHA(self):
        # Test data from RFC3141 section A.3.2
        self.run_test(
            hmac="sha",
            password="maplesyrup",
            intermediate_key="9f b5 cc 03 81 49 7b 37 93 52 89 39 ff 78 8d 5d 79 14 52 11",
            engineid="00 00 00 00 00 00 00 00 00 00 00 02",
            localized_key="66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f",
        )

    def test_RFC7630_SHA224(self):
        # Self-derived test data
        self.run_test(
            hmac="sha224",
            password="maplesyrup",
            intermediate_key=(
                "282a5867ee9aac639ad59df9572c7d3ac0fbc13a905b6df07dbbf00b"
            ),
            engineid="00 00 00 00 00 00 00 00 00 00 00 02",
            localized_key="0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674",
        )

    def test_RFC7630_SHA256(self):
        # Self-derived test data
        self.run_test(
            hmac="sha256",
            password="maplesyrup",
            intermediate_key=(
                "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac"
            ),
            engineid="00 00 00 00 00 00 00 00 00 00 00 02",
            localized_key=(
                "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"
            ),
        )

    def test_RFC7630_SHA384(self):
        # Self-derived test data
        self.run_test(
            hmac="sha384",
            password="maplesyrup",
            intermediate_key=(
                "e06eccdf2c68a06ed034723c9c26e0db3b669e1e2efed49150b55377a2e9"
                "8f383c86fb836857444654b287c93f51ff64"
            ),
            engineid="00 00 00 00 00 00 00 00 00 00 00 02",
            localized_key=(
                "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6"
                "f0455a53689a3937eea07319a633d2ccba78"
            ),
        )

    def test_RFC7630_SHA512(self):
        # Self-derived test data
        self.run_test(
            hmac="sha512",
            password="maplesyrup",
            intermediate_key=(
                "7e4396de5aadc77be853819b98c9406265b3a9c37cc3176569847a4e4f6f"
                "ba63dd3a73d04924d31a63f95a601f9385af6be4ed1b37f87d040f7c6ed6"
                "f8d38a91"
            ),
            engineid="00 00 00 00 00 00 00 00 00 00 00 02",
            localized_key=(
                "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84"
                "c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250ad"
                "fcffbb0b"
            ),
        )

    def run_test(self, hmac, password, intermediate_key, engineid, localized_key):
        expected_intermediate_bytes = bytes.fromhex(intermediate_key)
        computed_intermediate_bytes = derive_intermediate_key(
            hash_type=hmac, password=password
        )
        self.assertEqual(
            expected_intermediate_bytes, computed_intermediate_bytes
        ), "Failure generating intermediate key"

        expected_localized_bytes = bytes.fromhex(localized_key)
        computed_localized_bytes = localize_intermediate_key(
            hash_type=hmac,
            intermediate_key=computed_intermediate_bytes,
            engineid=engineid,
        )
        self.assertEqual(
            expected_localized_bytes, computed_localized_bytes
        ), "Failure localizing key"

        computed_localized_bytes = snmpv3_key_from_password(
            password=password, engineid=engineid, hash_type=hmac, hex_output=False
        )
        self.assertEqual(
            expected_localized_bytes, computed_localized_bytes
        ), "Failure computing key from password"


if __name__ == "__main__":
    unittest.main()
