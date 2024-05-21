# Susi Core

**Recommended Minimum Rust Version:** 1.76

Susi Core is a library that allows encryption and decryption of files to protect them from unauthorized parties. This project is expected to be integrated with other applications or even libraries. This library does the majority of the work in operating on files, including but not limited to managing worker threads and assigning tasks to them. Client projects will simply have to plug into the library's interfaces to start encrypting and decrypting files.

Files are encrypted to and decrypted from a custom file format called the Susi Encrypted File. Susi Core is not capable of encrypting nor decrypting other encryption file formats. See [Susi Software Specifications](#susi-software-specifications) to learn how to know more details about the file format.

## Supported Platforms
Susi Core is likely compilable in all modern versions of major desktop platforms (Windows, macOS, Linux). However, this project has only been compiled in Windows so far. Full support for the other major platforms are to be determined.

Additionally, only little-endian systems are supported currently.

## Development
To compile Susi Core, just run:

```bash
$ cd /path/to/susi/core
$ cargo build --debug # or --release for a release build
```

The compiled library (`susi_core.dll`) and related files (e.g. `susi_core.dll.lib`, `susi_core.pdb`) can be found in `target/debug` for debug builds (if any) and `target/release` for release builds (if any).

### Running Tests
Tests are available for Susi Core. To run these tests, simply run:

```bash
$ cd /path/to/susi/core
$ cargo test
```

## Integration into Projects
Documentation on integrating with other projects is still lacking. Those who would like to integrate Susi Core into their own projects as a DLL may check out the [Susi GUI (for Windows)](https://github.com/seanballais/susi-gui-windows) project for guidance.

## Susi Software Specifications
Software specifications for Susi have been written to guide us with the development of the project. It also contains the specifications of the file format of a Susi Encrypted File (`.ssef`). If you are interested in reading it or learning about the file format, you may obtain and read the latest specifications from the ["Releases" page of the software specifications's repository](https://github.com/seanballais/susi-software-specs/releases).

## License
Susi Core is licensed under the Mozilla Public License 2.0. See [LICENSE.md](/LICENSE.md) for details.

## Contact
Sean Francis N. Ballais - [@seanballais](https://twitter.com/seanballais) - [sean@seanballais.com](mailto:sean@seanballais.com)
