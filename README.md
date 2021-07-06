# reduced-quantum-aes-circuits
A repository for code used in the paper "Improvements to quantum search techniques for block-ciphers, with applications to AES" (accepted at SAC2020) by James H. Davenport and Benjamin Pring.

The code was originally written for Microsoft.Quantum.Sdk/0.14.2011120240, but has since been refactored slightly for Microsoft.Quantum.Sdk/0.18.2106148911 which fixes several bugs with the Microsoft Q# resource estimation routines. Because of changes to Q#, the reported values may differ slightly from those reported in the original paper - but both the theory and reported gains stand.

To run tests for correctness of components and resource estimation routines in Linux:
1) dotnet build
2) dotnet run --no-build
