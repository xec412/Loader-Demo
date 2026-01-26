# Loader-Demo
Windows internals–focused loader demo built with low-level C

Loader-Demo is a **Windows user-mode research project** developed for educational and demonstration purposes.
The project focuses on exploring low-level Windows internals, process interaction mechanisms, and loader-related techniques
in a controlled and non-operational context.

This repository is intended to demonstrate understanding of advanced Windows concepts and is **not designed for real-world deployment**.

---

## Features

- ChaCha20-based payload encryption
- UUID-based payload handling
- IAT hiding and camouflage techniques
- Direct system calls using Hell’s Gate–style resolution
- Custom string hashing for API resolution
- NTDLL unhooking via clean KnownDll mapping
- CRT-free binary (custom implementations, no MSVCRT dependency)

---

## Disclaimer

⚠️ **IMPORTANT NOTICE**

This project is provided **strictly for educational and research purposes only**.

- The code is intended to demonstrate Windows internals, loader behavior, and low-level programming concepts.
- It is **not intended to be used in production environments**.
- Any misuse of this code for malicious or illegal activities is **strictly prohibited**.
- The author **does not take any responsibility** for damages, data loss, legal consequences, or misuse resulting from the use of this project.

By accessing or using this repository, you acknowledge that you are solely responsible for how the code is used and agree to comply with all applicable laws and regulations.

---

## License

This project is licensed under the **MIT License**.
See the `LICENSE` file for details.
