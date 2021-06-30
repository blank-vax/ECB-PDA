# ECB-PDA

ECB-PDA: Edge Computing Based Privacy Data Aggregation. This is a simulation project of our privacy data aggregation scheme referring to LVPDA. In our scheme,we combine edge computing with traditional privacy data aggregation architecture,raising new Sensor-Edge Server-Cloud Server three-tiers layer structure. We use Java for the simulation of our scheme, also JPBC library is used for bilinear pairing operation, homomorphic algorithm and ZSS short signature. In order to simply simulate the process of our scheme, 1STD-1ES-1CC structure is used during the simulation process.

## Project Structure

### Parameters_file

We use the dat file to save some operation result and intermediate parameters.

### ElGamal_Cryptosystem

In this folder, we construct a ElGamalDemo to achieve EC-ElGamal algorithm. Also, the file Pairing_Test is a test class.

### Operation_Estimation

In this folder, Estimation class is used for estimating the consuming time of separate operation involved in this project.

### Paillier_Cryptosystem

This folder only involves PaillierDemo, which is the achievement of Paillier homomorphic algorithm.

### Other Class

* BLS

  The achievement of BLS signature.

* CC

  Variables and methods of entity Control Center.

* ChameleonHash

  Some sub-functions in ChameleonHash function.

* ES

  Variables and methods of entity Edge Server.

* JPBCDemo

  Demo for simple usage of JPBC library.

* new_PDA

  Main class for the whole project.

* SD

  Variables and methods of entity Smart Devices.

* TrustAuthority

  Variables and methods of entity Trust Authority.

* Util

  Some useful and efficient functions used in our project, including some transform function, hash function, and file I/O function.

* TimeCountProxyHandle

  Timing function for time count.
