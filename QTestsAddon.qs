// Modified rounds for AES STO approach in paper "Improvements to quantum search techniques for block-ciphers, with applications to AES" by JH Davenport and B Pring


namespace QTestsAddon
{
    open Microsoft.Quantum.Intrinsic;
    open QUtilities;

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Measurement;
    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Math;
    open Microsoft.Quantum.Logical;
    open Microsoft.Quantum.Random;

    // 

    // create a random bool array by Hadamard transform and measurement
    operation PrepareRandomBoolArray(numBits : Int) : Bool[]
    {
        mutable answer = new Bool[0];
        for i in 0..numBits
        {
            if (DrawRandomDouble(0.0,1.0) >= 0.5)
            {
                set answer += [true];
            }
            else
            {
                set answer += [false];
            }
        }
        return answer;        
    }

    // Standard QDK function from microsoft docs
    operation PrepareBitString(bitstring : Bool[], register : Qubit[]) : Unit
    is Adj + Ctl {
        let nQubits = Length(register);
        for idxQubit in 0..nQubits - 1
        {
            if (bitstring[idxQubit]) 
            {
                X(register[idxQubit]);
            }
        }
    }

    operation Resource_TestMixColumnsIn(output_byte : Int) :  Unit
    {
        use register = Qubit[32]
        {
            MixColumnAddon.MixByteIn(register, output_byte , true); // free swaps = true as we are testing resources
        }
    }
    

    // Test a selection of inputs (32 bits) on MixByteIn using the Toffoli simulator and reference in-place MixColumns implementation
    operation Correctness_TestMixColumnsIn(numTests : Int) : Bool
    {
        mutable all_answers_match = true;
        for i in 1..numTests
        {
            mutable test_bitstring = DrawRandomInt(0,2^32); 
            use register = Qubit[32]
            {
                PrepareBitString(IntAsBoolArray(test_bitstring,32), register);

                QAES.InPlace.MixWord(register,true);
                let reference = MultiM(register);
                Adjoint QAES.InPlace.MixWord(register,false); 

                MixColumnAddon.MixByteIn(register,1,false);
                let test_1 = MultiM(register);
                Adjoint MixColumnAddon.MixByteIn(register,1,false);

                MixColumnAddon.MixByteIn(register,2,false);
                let test_2 = MultiM(register);
                Adjoint MixColumnAddon.MixByteIn(register,2,false);

                MixColumnAddon.MixByteIn(register,3,false);
                let test_3 = MultiM(register);
                Adjoint MixColumnAddon.MixByteIn(register,3,false);
                
                MixColumnAddon.MixByteIn(register,4,false);
                let test_4 = MultiM(register);
                Adjoint MixColumnAddon.MixByteIn(register,4,false);

                if (EqualA(EqualR, reference[0..7], test_1[0..7]) and EqualA(EqualR, reference[8..15], test_2[0..7]) and EqualA(EqualR, reference[16..23], test_3[0..7]) and EqualA(EqualR, reference[24..31], test_4[0..7]))
                {
                    //Message($"Test passed on input {test_bitstring} interpreted as 32 bits! Reference and test output bits..");
                    //Message($"{reference[0..31]}");
                    //Message($"{test_1[0..7] + test_2[0..7] + test_3[0..7] + test_4[0..7]}");
                }
                else
                {
                    Message($"MixColumns implementations do not match on input {test_bitstring} interpreted as 32 bits!");
                    //Message($"{reference[0..31]}");
                    //Message($"{test_1[0..7] + test_2[0..7] + test_3[0..7] + test_4[0..7]}");
                    set all_answers_match = false;
                }
                

                ResetAll(register);
            }
        }
        return all_answers_match;
    }


    // Checks for correctness of our modification by comparing the computed output bits for random keys and plaintexts against the reference implementation.
    operation Correctness_CustomAES(Nr : Int, Nk : Int, numTests : Int) : Bool
    {
        mutable all_answers_match = true;
        for i in 1..numTests
        {
            // create random bool arrays here in stead
            mutable test_plaintext = PrepareRandomBoolArray(128);
            mutable test_key       = PrepareRandomBoolArray(Nk*32); 

            mutable result_CustomForwardRijndael    = new Result[32];
            mutable result_CustomForwardRijndael_Maximov = new Result[32];
            mutable result_ReferenceForwardRijndael = new Result[32];
            mutable result_ReferenceForwardRijndaelFull = new Result[128];
            mutable result_ExpensiveForwardRijndael = new Result[128];

            use (state_register , key_register) = (Qubit[128 + (Nr-2)*128 + 64], Qubit[32*Nk])
            {
                // Load plaintext
                PrepareBitString(test_plaintext, state_register[0..(32-1)]);
                // Load key
                PrepareBitString(test_key,       key_register[0..(Nk*32 -1)]);
                
                //Message("Starting CustomForward");
                QAES.CustomForwardRijndael(key_register, state_register, Nr, Nk, true, false);
                //Message("CustomForward completed");
                let temp = MultiM(state_register);
                //set result_CustomForwardRijndael = temp[(128 + (Nr-2)*128 + 32)..(128 + (Nr-2)*128 + 63)];
                set result_CustomForwardRijndael = temp[(4*32*(Nr-1) + 1*32)..(4*32*(Nr-1) + 2*32 - 1)];
                //Message("Starting Adjoint CustomForward");
                Adjoint QAES.CustomForwardRijndael(key_register, state_register, Nr, Nk,true,  false);
                //Message("Adjoint CustomForward completed");

                ResetAll(state_register);
                ResetAll(key_register);
            } 

            use (state_register , key_register) = (Qubit[8*32*(Nr-4) + 19*32], Qubit[32*Nk])
            {
                // Load plaintext
                PrepareBitString(test_plaintext, state_register[0..(32-1)]);
                // Load key
                PrepareBitString(test_key,       key_register[0..(Nk*32 -1)]);
                
                //Message("Starting CustomForward");
                QAES.CustomForwardRijndael(key_register, state_register, Nr, Nk, false, false);
                //Message("CustomForward completed");
                let temp = MultiM(state_register);
                //set result_CustomForwardRijndael_Maximov = temp[(8*32*(Nr-4) + 18*32)..(8*32*(Nr-4) + 19*32-1)];
                set result_CustomForwardRijndael_Maximov = temp[(8*32*(Nr-4) + 18*32 )..(8*32*(Nr-4) + 19*32 - 1)];
                //Message("Starting Adjoint CustomForward");
                Adjoint QAES.CustomForwardRijndael(key_register, state_register, Nr, Nk,false,  false);
                //Message("Adjoint CustomForward completed");

                ResetAll(state_register);
                ResetAll(key_register);
            } 

            use (state_register , key_register) = (Qubit[(Nr+1)*128], Qubit[32*Nk])
            {
                // Load plaintext
                PrepareBitString(test_plaintext, state_register[0..32-1]);
                // Load key
                PrepareBitString(test_key,       key_register[0..(Nk*32 -1)]);

                QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, true, false);
                let temp = MultiM(state_register);
                set result_ReferenceForwardRijndaelFull = temp[((Nr)*128)..((Nr+1)*128 -1)];
                set result_ReferenceForwardRijndael = 
                temp[Nr*128..(Nr*128 + 7)] + 
                temp[(Nr*128 + 3*32 + 1*8)..(Nr*128 + 3*32 + 2*8-1)] +
                temp[(Nr*128 + 2*32 + 2*8)..(Nr*128 + 2*32 + 3*8-1)] +
                temp[(Nr*128 + 1*32 + 3*8)..(Nr*128 + 1*32 + 4*8-1)];
                Adjoint QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, true, false);

                ResetAll(state_register);
                ResetAll(key_register);
            } 

            use (state_register , key_register) = (Qubit[128 + (Nr-3)*128], Qubit[32*Nk])
            {
                // Load plaintext
                PrepareBitString(test_plaintext, state_register[0..(32-1)]);
                // Load key
                PrepareBitString(test_key,       key_register[0..(Nk*32 -1)]);
                
                //Message("Starting CustomForward");
                QAES.ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, false);
                //Message("CustomForward completed");
                let temp = MultiM(state_register); 
                set result_ExpensiveForwardRijndael = temp[(128 + 4*32*(Nr-4) + 0*32)..(128 + 4*32*(Nr-4) + 127)];
                //Message("Starting Adjoint CustomForward");
                Adjoint QAES.ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, false);
                //Message("Adjoint CustomForward completed");

                ResetAll(state_register);
                ResetAll(key_register);
            } 



            if (not EqualA(EqualR, result_CustomForwardRijndael, result_ReferenceForwardRijndael))
            {
                set all_answers_match = false;
                // Message($"0 {result_CustomForwardRijndael[0..7]}");
                // Message($"0 {result_ReferenceForwardRijndael[0..7]}");
                // Message($"1 {result_CustomForwardRijndael[8..15]}");
                // Message($"1 {result_ReferenceForwardRijndael[8..15]}");
                // Message($"2 {result_CustomForwardRijndael[16..23]}");
                // Message($"2 {result_ReferenceForwardRijndael[16..23]}");
                // Message($"3 {result_CustomForwardRijndael[24..31]}");
                // Message($"3 {result_ReferenceForwardRijndael[24..31]}");
            }

            if (not EqualA(EqualR, result_ReferenceForwardRijndaelFull, result_ExpensiveForwardRijndael))
            {
                set all_answers_match = false;
                // Message("Expensive Oracle output does not match reference oracle output");
                // Message($"0 {result_ReferenceForwardRijndaelFull[0..31]}");
                // Message($"0 {result_ExpensiveForwardRijndael[0..31]}");
                // Message($"1 {result_ReferenceForwardRijndaelFull[32..63]}");
                // Message($"1 {result_ExpensiveForwardRijndael[32..63]}");
                // Message($"2 {result_ReferenceForwardRijndaelFull[64..91]}");
                // Message($"2 {result_ExpensiveForwardRijndael[64..91]}");
                // Message($"3 {result_ReferenceForwardRijndaelFull[92..127]}");
                // Message($"3 {result_ExpensiveForwardRijndael[92..127]}");
                // Message($"*** {result_ReferenceForwardRijndaelFull}");
                // Message($"*** {result_ExpensiveForwardRijndael}");
            }
            if (not EqualA(EqualR, result_CustomForwardRijndael, result_CustomForwardRijndael_Maximov))
            {
                set all_answers_match = false;
                // Message("Expensive Oracle output does not match reference oracle output");
                // Message($"0 {result_ReferenceForwardRijndaelFull[0..31]}");
                // Message($"0 {result_ExpensiveForwardRijndael[0..31]}");
                // Message($"1 {result_ReferenceForwardRijndaelFull[32..63]}");
                // Message($"1 {result_ExpensiveForwardRijndael[32..63]}");
                // Message($"2 {result_ReferenceForwardRijndaelFull[64..91]}");
                // Message($"2 {result_ExpensiveForwardRijndael[64..91]}");
                // Message($"3 {result_ReferenceForwardRijndaelFull[92..127]}");
                // Message($"3 {result_ExpensiveForwardRijndael[92..127]}");
                // Message($"*** {result_ReferenceForwardRijndaelFull}");
                // Message($"*** {result_ExpensiveForwardRijndael}");
            }
            //Message($"!!! {result_ReferenceForwardRijndaelFull}");
            //Message($"*** {result_ExpensiveForwardRijndael}");
            // Message($"0 {result_CustomForwardRijndael[0..7]}");
            // Message($"0 {result_ReferenceForwardRijndael[0..7]}");
            // Message($"1 {result_CustomForwardRijndael[8..15]}");
            // Message($"1 {result_ReferenceForwardRijndael[8..15]}");
            // Message($"2 {result_CustomForwardRijndael[16..23]}");
            // Message($"2 {result_ReferenceForwardRijndael[16..23]}");
            // Message($"3 {result_CustomForwardRijndael[24..31]}");
            // Message($"3 {result_ReferenceForwardRijndael[24..31]}");


            //Message($"0 {result_CustomForwardRijndael[0..127]}");
            //Message($"0 {result_CustomForwardRijndael}");

            //Message($"1 {result_CustomForwardRijndael_Maximov[0..127]}");
            //Message($"1 {result_CustomForwardRijndael_Maximov[128..159]}");
            //Message($"1 {result_CustomForwardRijndael_Maximov}");

        
        }


        return all_answers_match;
    }



    // Use a dummy key for costs
    operation CostCheapGroverOracle(Nr: Int, Nk: Int, in_place_mixcolumn : Bool, costing: Bool) : Unit
    {
        mutable dummy_text = new Bool[0];
        for i in 0..127
        {
            set dummy_text += [true];
        }
        use (key_register, success) = (Qubit[32*Nk],Qubit())
        {
            QAES.CheapGroverOracle(key_register, success, dummy_text, dummy_text, Nr, Nk, in_place_mixcolumn, true);
        }

    }

     // Use a dummy key for worst-case costs. 
     // r - number of plaintext/ciphertext pairs
    operation CostSerialGroverOracle(Nr: Int, Nk: Int, r : Int, in_place_mixcolumn : Bool, costing: Bool) : Unit
    {
        mutable temp = new Bool[0];

        for i in 0..127
        {
            set temp += [true];
        }
        mutable dummy_text = [temp];
        for i in 1..(r-1)
        {
            set dummy_text += [temp];
        }

        use (key_register, success) = (Qubit[32*Nk],Qubit())
        {
            QAES.SerialGroverOracle(key_register, success, dummy_text, dummy_text, Nr, Nk, in_place_mixcolumn,  true);
        }

    }

    // Use a dummy key for worst-case costs. 
     // r - number of plaintext/ciphertext pairs
    operation CostExpensiveSerialGroverOracle(Nr: Int, Nk: Int, r : Int, costing : Bool) : Unit
    {
        mutable temp = new Bool[0];

        for i in 0..127
        {
            set temp += [true];
        }
        mutable dummy_text = [temp];
        for i in 1..(r-1)
        {
            set dummy_text += [temp];
        }

        use (key_register, success) = (Qubit[32*Nk],Qubit())
        {
            QAES.ExpensiveSerialGroverOracle(key_register, success, dummy_text, dummy_text, Nr, Nk, costing);
        }

    }

}