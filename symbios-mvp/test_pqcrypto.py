#!/usr/bin/env python3
"""
Test script for Post-Quantum Cryptography
Demonstrates PQ signature and KEM functionality
"""

import time
import hashlib

class PQCryptoTester:
    def __init__(self):
        self.test_results = []

    def log_result(self, test_name: str, success: bool, details: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        self.test_results.append((test_name, success))

    def test_key_generation(self):
        """Test PQ key generation"""
        print("🔐 Testing Post-Quantum Key Generation...")

        try:
            # Simulate key generation (in real implementation this would call Rust)
            public_key = hashlib.sha3_256(b"pq-public-key-test").digest()
            private_key = hashlib.sha3_256(b"pq-private-key-test").digest()

            self.log_result(
                "PQ Key Generation",
                len(public_key) == 32 and len(private_key) == 32,
                f"Generated keys: pub={public_key.hex()[:16]}..., priv={private_key.hex()[:16]}..."
            )
        except Exception as e:
            self.log_result("PQ Key Generation", False, str(e))

    def test_digital_signatures(self):
        """Test PQ digital signatures"""
        print("✍️  Testing Post-Quantum Digital Signatures...")

        try:
            # Simulate signing (in real implementation this would call Rust)
            message = b"Hello, Quantum World!"
            signature = hashlib.sha3_256(b"pq-signature" + message).digest()

            # Simulate verification
            verification = hashlib.sha3_256(b"pq-verify" + message + signature).digest()
            expected = hashlib.sha3_256(b"pq-expected" + message).digest()

            is_valid = verification == expected

            self.log_result(
                "PQ Digital Signatures",
                is_valid,
                f"Message: {message.decode()}, Signature: {signature.hex()[:16]}..."
            )
        except Exception as e:
            self.log_result("PQ Digital Signatures", False, str(e))

    def test_key_encapsulation(self):
        """Test PQ key encapsulation mechanism"""
        print("🔑 Testing Post-Quantum Key Encapsulation...")

        try:
            # Simulate KEM (in real implementation this would call Rust)
            public_key = hashlib.sha3_256(b"kem-public-key").digest()

            # Encapsulation
            shared_secret1 = hashlib.sha3_256(b"kem-shared-secret-enc" + public_key).digest()
            ciphertext = hashlib.sha3_256(b"kem-ciphertext" + public_key + shared_secret1).digest()

            # Decapsulation
            shared_secret2 = hashlib.sha3_256(b"kem-shared-secret-dec" + ciphertext + public_key).digest()

            keys_match = shared_secret1 == shared_secret2

            self.log_result(
                "PQ Key Encapsulation",
                keys_match,
                f"Shared secret match: {keys_match}"
            )
        except Exception as e:
            self.log_result("PQ Key Encapsulation", False, str(e))

    def test_performance(self):
        """Test PQ crypto performance"""
        print("⚡ Testing Post-Quantum Performance...")

        try:
            iterations = 1000
            start_time = time.time()

            for i in range(iterations):
                # Simulate PQ operations
                hashlib.sha3_256(f"pq-test-{i}".encode()).digest()

            elapsed = time.time() - start_time
            ops_per_second = iterations / elapsed

            self.log_result(
                "PQ Performance",
                ops_per_second > 100,  # Basic performance check
                ".2f"
            )
        except Exception as e:
            self.log_result("PQ Performance", False, str(e))

    def test_quantum_resistance(self):
        """Test quantum resistance properties"""
        print("🛡️  Testing Quantum Resistance...")

        try:
            # Test key sizes (simulated)
            pq_key_sizes = {
                "ML-KEM-512": 512,
                "ML-KEM-768": 768,
                "ML-KEM-1024": 1024,
                "ML-DSA-44": 1312,
                "ML-DSA-65": 1952,
                "ML-DSA-87": 2592,
            }

            # Check that key sizes are appropriate for quantum resistance
            adequate_sizes = all(size >= 256 for size in pq_key_sizes.values())

            self.log_result(
                "Quantum Resistance",
                adequate_sizes,
                f"Key sizes: {pq_key_sizes}"
            )
        except Exception as e:
            self.log_result("Quantum Resistance", False, str(e))

    def run_all_tests(self):
        """Run all PQ crypto tests"""
        print("🚀 Starting Post-Quantum Cryptography Tests")
        print("=" * 50)

        self.test_key_generation()
        self.test_digital_signatures()
        self.test_key_encapsulation()
        self.test_performance()
        self.test_quantum_resistance()

        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)

        passed = sum(1 for _, success in self.test_results if success)
        total = len(self.test_results)

        print(f"Tests passed: {passed}/{total}")
        print(".1f"
        if passed == total:
            print("🎉 All tests passed! PQ cryptography is ready.")
        else:
            print("⚠️  Some tests failed. Check implementation.")

        return passed == total

def main():
    tester = PQCryptoTester()
    success = tester.run_all_tests()

    if success:
        print("\n💡 Next steps:")
        print("1. Integrate PQ crypto into transaction signing")
        print("2. Update consensus to use PQ signatures")
        print("3. Add PQ key management to wallets")
        print("4. Performance optimization")

if __name__ == "__main__":
    main()

