// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;
using System.Collections.Generic;
using System.Diagnostics;


using Microsoft.Quantum.Simulation.Core;
using Microsoft.Quantum.Simulation.Simulators;
using Microsoft.Quantum.Simulation.Simulators.QCTraceSimulators;

using FileHelpers;
using CommaSeparated;

using Microsoft.Quantum.QsCompiler.SyntaxTree;
using Microsoft.Quantum.QsCompiler.Transformations.SyntaxTreeTrimming;

namespace cs
{
    class Driver
    {
        static void Main(string[] args)
        {
            // estimating costs and checking for correctness

            Console.WriteLine("Testing the correctness of MixByteIn on 16 random inputs against the reference implementation...");
            {
                var toffoliSim = new ToffoliSimulator();
                
                var resultMixByteIn = QTestsAddon.Correctness_TestMixColumnsIn.Run(toffoliSim,16).Result;
                if (resultMixByteIn == true)
                {
                    System.Console.WriteLine("MixByte tests: OK!");
                }
                else
                {
                    System.Console.WriteLine("MixByte tests: PROBLEM DETECTED! Some inputs do not match.");
                }
            }
            Console.WriteLine("");

            Console.WriteLine("Testing the correctness of CustomAES on 16 different (key,plaintext) pairs against the reference implementation...");
            {
                var toffoliSim = new ToffoliSimulator();
                
                var resultMixByteIn = QTestsAddon.Correctness_CustomAES.Run(toffoliSim,10,4,16).Result;
                if (resultMixByteIn == true)
                {
                    System.Console.WriteLine("CustomAES-128 for producing only four bytes of cipertext: OK!");
                    System.Console.WriteLine("Lower qubit/higher gates version of AES-128: OK!");
                    System.Console.WriteLine("Maximov low depth CustomAES-128 for producing only four bytes of ciphertext: OK!");

                }
                else
                {
                    System.Console.WriteLine("CustomAES-128: PROBLEM DETECTED! Some inputs do not match.");
                }
            }
            {
                var toffoliSim = new ToffoliSimulator();
                
                var resultMixByteIn = QTestsAddon.Correctness_CustomAES.Run(toffoliSim,12,6,16).Result;
                if (resultMixByteIn == true)
                {
                    System.Console.WriteLine("CustomAES-192 for producing only four bytes of cipertext: OK!");
                    System.Console.WriteLine("Lower qubit/higher gates version of AES-192: OK!");
                    System.Console.WriteLine("Maximov low depth CustomAES-192 for producing only four bytes of ciphertext: OK!");

                }
                else
                {
                    System.Console.WriteLine("CustomAES-192: PROBLEM DETECTED! Some inputs do not match.");
                }
            }
            {
                var toffoliSim = new ToffoliSimulator();
                
                var resultMixByteIn = QTestsAddon.Correctness_CustomAES.Run(toffoliSim,14,8,16).Result;
                if (resultMixByteIn == true)
                {
                    System.Console.WriteLine("CustomAES-256 for producing only four bytes of cipertext: OK!");
                    System.Console.WriteLine("Lower qubit/higher gates version of AES-256: OK!");
                    System.Console.WriteLine("Maximov low depth CustomAES-256 for producing only four bytes of ciphertext: OK!");
                }
                else
                {
                    System.Console.WriteLine("CustomAES-256: PROBLEM DETECTED! Some inputs do not match.");
                }

                Console.WriteLine("Correctness tests completed!");
            }



            int limit = 1;
            Console.WriteLine("");
            Console.WriteLine("Resources required for Cheap quantum oracle with in place MixColumns. r = 1:");
            //Console.Write("operation, CNOT count, 1-qubit Clifford count, T count, R count, M count, T depth, initial width, extra width, comment, full depth");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostCheapGroverOracle<QAES.CheapGroverOracle>(string.Format("Cheap quantum oracle for AES-128 --- in place MixColumns"),10,4,true);
            }
            Console.WriteLine("");

            for (int i = 0; i < limit; i++)
            {
                Estimates.CostCheapGroverOracle<QAES.CheapGroverOracle>(string.Format("Cheap quantum oracle for AES-192 --- in place MixColumns"),12,6,true);
            }
            Console.WriteLine("");

            for (int i = 0; i < limit; i++)
            {
                Estimates.CostCheapGroverOracle<QAES.CheapGroverOracle>(string.Format("Cheap quantum oracle for AES-256 --- in place MixColumns"),14,8,true);
            }
            Console.WriteLine("");
            Console.WriteLine("");

            Console.WriteLine("");
            Console.WriteLine("Resources required for Cheap quantum oracle with out of place MixColumns with r = 1:");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostCheapGroverOracle<QAES.CheapGroverOracle>(string.Format("Cheap quantum oracle for AES-128 --- out of place MixColumns"),10,4,false);
            }
            Console.WriteLine("");

            for (int i = 0; i < limit; i++)
            {
                Estimates.CostCheapGroverOracle<QAES.CheapGroverOracle>(string.Format("Cheap quantum oracle for AES-192 --- out of place MixColumns"),12,6,false);
            }
            Console.WriteLine("");

            for (int i = 0; i < limit; i++)
            {
                Estimates.CostCheapGroverOracle<QAES.CheapGroverOracle>(string.Format("Cheap quantum oracle for AES-256 --- out of place MixColumns"),14,8,false);
            }
            Console.WriteLine("");
            Console.WriteLine("");

            Console.WriteLine("Resources required for Serial quantum oracle with in place MixColumns. r = 2:");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-128 --- in place MixColumns"),10,4,2,true);
            }
            Console.WriteLine("");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-192 --- in place MixColumns"),12,6,2,true);
            }
            Console.WriteLine("");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-256 --- in place MixColumns"),14,8,2,true);
            }
            Console.WriteLine("");
            Console.WriteLine("");

            Console.WriteLine("");
            Console.WriteLine("Resources required for Serial quantum oracle with out of place Mixcolumns. r = 2:");
            Console.WriteLine("");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-128 --- out of place MixColumns"),10,4,2,false);
            }
            Console.WriteLine("");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-192 --- out of place MixColumns"),12,6,2,false);
            }
            Console.WriteLine("");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-256 --- out of  place MixColumns"),14,8,2,false);
            }
            Console.WriteLine("");
            Console.WriteLine("");

            Console.WriteLine("Resources required for Expensive Serial quantum oracle with in place Mixcolumns. r = 2:");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostExpensiveSerialGroverOracle<QAES.ExpensiveSerialGroverOracle>(string.Format("Expensive Serial quantum oracle for AES-128"),10,4,2,true);
            }
            Console.WriteLine("");

            for (int i = 0; i < limit; i++)
            {
                Estimates.CostExpensiveSerialGroverOracle<QAES.ExpensiveSerialGroverOracle>(string.Format("Expensive Serial quantum oracle for AES-192"),12,6,2,true);
            }
            Console.WriteLine("");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostExpensiveSerialGroverOracle<QAES.ExpensiveSerialGroverOracle>(string.Format("Expensive Serial quantum oracle for AES-256"),14,8,2,true);
            }
            Console.WriteLine();



            Console.WriteLine("");
            Console.WriteLine("Serial quantum oracle for AES-256, in place r = 3");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-256 --- in place MixColumns r = 3"),14,8,3,true);
            }
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("Serial quantum oracle for AES-256, out of place r = 3");
            for (int i = 0; i < limit; i++)
            {
                Estimates.CostSerialGroverOracle<QAES.SerialGroverOracle>(string.Format("Serial quantum oracle for AES-256 --- out of place MixColumns r = 3"),14,8,3,false);
            }
            Console.WriteLine("");

        }
    }
}