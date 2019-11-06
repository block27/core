# Sigma HSM
This source repository contains the code used for creating, signing and encrypting keys and data through the "pseudo" HSM module authored by Alex Manelis. 

## General
Below are the main points to be noted on the HSM that can be broken down into their own detailed sections.

- **PSEUDO**, meaning that the keys are generated in a secure hardware environment, but encrypted with a custom Sigma KEY/IV device used to AES encrypt/decrypt pems and store them for safe backup. There is available an AES VHDL package that can be used to generate the keys on FPGA, but that has been a challenge to fetch keys and back them up.

-  **RANDOMNESS**, when generating the ECDSA/RSA assymetric keys, the device needs the highest possible amount of entropy. It gains this through the use of two devices cabable of creating close to. 7.9999 bits of Entropy per byte. The first, `/dev/TrueRNG` is capaable of speeds around 3 mb/s. The second is the BitBlabber, `/dev/BB` capable of speeds around 20 mb/s. These have been mapped into the `crypto/rand` module `io.Reader` interface and used directly in Sigma to generate the keys. 

- **FPGA**, the motherboard here that will be used to run the application code is a DEC10-NANO from TerASIC. It is capable of complete VHDL  programming and hardware managment by switches on board. Plan of importance on methods of implementation below:
	-  Implement complete golang code base capable of generating soft keys (meaning they can be accessed and passed around only inside of the HSM). These can be encrypted via AES and safely backed up.
	
	-  Second is to implement completely in hardware using VHDL.  This is harder,  but possible.

	-  After either are completed, build out Serial API  so the device can be connected to HSM API via USB only.

	 

The main goal here is to build an HSM like device that can securly generate keys, but also give the ability to back up keys. It's important to note that what is currentlty available on the market is hard to use, minimally documented, bad libraries and very very expensive. I believe it can be done better and safer from a standpoint of hardware failure.