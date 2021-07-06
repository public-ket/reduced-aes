// Modified rounds for AES STO approach in paper "Improvements to quantum search techniques for block-ciphers, with applications to AES" by JH Davenport and B Pring

namespace QAES
{
    open Microsoft.Quantum.Intrinsic;
    open QUtilities;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Logical;

    open Microsoft.Quantum.Measurement;


    // AntePenultimateRound assumes the input is the same as the normal antepenultimate round. Altered Microsoft grover-blocks code
    // in_state  --- 128 bits [4][32]
    // out_state --- 128 bits [4][32]
    operation AntePenultimateRound(in_state: Qubit[][], out_state: Qubit[][], key: Qubit[], round: Int, Nk : Int, costing: Bool) : Unit
    {
        body (...)
        {
            // Do all 16 S-Boxes as normal
            QAES.ByteSub(in_state, out_state, costing);
            // ShiftRows as normal
            QAES.InPlace.ShiftRow(out_state, costing);
            // Apply special MixByte operations as we only want to output 4 specific bytes.
            MixColumnAddon.MixByteIn(out_state[0][0..7] + out_state[0][8..15] + out_state[0][16..23] + out_state[0][24..31], 1, costing);
            MixColumnAddon.MixByteIn(out_state[1][0..7] + out_state[1][8..15] + out_state[1][16..23] + out_state[1][24..31], 2, costing);
            MixColumnAddon.MixByteIn(out_state[2][0..7] + out_state[2][8..15] + out_state[2][16..23] + out_state[2][24..31], 3, costing);
            MixColumnAddon.MixByteIn(out_state[3][0..7] + out_state[3][8..15] + out_state[3][16..23] + out_state[3][24..31], 4, costing);

            if (Nk == 4)
            {
                // AES128
                QAES.InPlace.KeyExpansion(key, round, Nk, 0, Nk-1, costing);
                // A slightly reduced AddRoundKey (negligible impact, but may as well optimise)
                for i in 0..7
                {
                    CNOT(key[0*8 + i], out_state[0][i]);
                }
                for i in 0..7
                {
                    CNOT(key[5*8 + i], out_state[1][i]);
                }
                for i in 0..7
                {
                    CNOT(key[10*8 + i], out_state[2][i]);
                }
                for i in 0..7
                {
                    CNOT(key[15*8 + i], out_state[3][i]);
                }
            }
            elif (Nk == 6)
            {
                // AES192
                if (round % 3 == 1)
                {
                    // shallowest variant found so far (if used in combination with others key_round varinats)
                    let key_round = (round/3) * 2 + 1;
                    if (round > 1)
                    {
                        QAES.InPlace.KeyExpansion(key, key_round, Nk, 2*Nk/3, Nk-1, costing);
                    }
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, 1, costing);
                    for i in 0..7
                    {
                        CNOT(key[4*32 + i], out_state[0][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[5*32 + 1*8 + i], out_state[1][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[0*32 + 2*8 + i], out_state[2][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[1*32 + 3*8 +i], out_state[3][i]);
                    }
                }
                elif (round % 3 == 2)
                {
                    let key_round = (round/3) * 2 + 1;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 2, Nk-1, costing);
                    for i in 0..7
                    {
                        CNOT(key[2*32 + 0*8 + i], out_state[0][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[3*32 + 1*8 + i], out_state[1][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[4*32 + 2*8 + i], out_state[2][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[5*32 + 3*8 + i], out_state[3][i]);
                    }
                }
                else
                {
                    let key_round = (round/3) * 2;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, 2*Nk/3-1, costing);
                    for i in 0..7
                    {
                        CNOT(key[0*32 + 0*8 + i], out_state[0][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[1*32 + 1*8 + i], out_state[1][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[2*32 + 2*8 + i], out_state[2][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[3*32 + 3*8 + i], out_state[3][i]);
                    }
                }
            }
            elif (Nk == 8)
            {
                // AES256
                if (round % 2 == 0)
                {
                    let key_round = round/2;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, Nk/2-1, costing);
                    for i in 0..7
                    {
                        CNOT(key[0*32 + 0*8 + i], out_state[0][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[1*32 + 1*8 + i], out_state[1][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[2*32 + 2*8 + i], out_state[2][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[3*32 + 3*8 + i], out_state[3][i]);
                    }
                }
                else
                {
                    if (round > 2)
                    {
                        let key_round = round/2;
                        Message("Diagnosics");
                        Message($"{Length(key)}");
                        Message($"{key_round}");
                        Message($"{Nk}");
                        Message($"{Nk/2}");
                        Message($"{Nk-1}");
                        Message("");
                        QAES.InPlace.KeyExpansion(key, key_round, Nk, Nk/2, Nk-1, costing);
                    }
                    for i in 0..7
                    {
                        CNOT(key[4*32 + 0*8 + i], out_state[0][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[5*32 + 1*8 + i], out_state[1][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[6*32 + 2*8 + i], out_state[2][i]);
                    }
                    for i in 0..7
                    {
                        CNOT(key[7*32 + 3*8 + i], out_state[3][i]);
                    }
                }
            } 
        }
        adjoint auto;
    }

    // PenultimateRound assumes that the input bytes are 0,5,10 and 15 of the original Penultimate round input
    // in_state  --- 32 bits  [32]
    // out_state --- 32 bits  [32] if using in-place     mixword, we use bits 0..
    // out_state --- 64 bits  [64] if using out-of-place mixword, we use bits 0..31 for the actual output
    operation PenultimateRound(in_state: Qubit[], out_state: Qubit[], key: Qubit[], round: Int, Nk : Int, in_place_mixcolumn : Bool, costing: Bool) : Unit
    {
        body (...)
        {
            // Perform only 4 S-Boxes instead of 16
            QAES.SubByte(in_state, out_state[0..31], costing);
            // ShiftRows is a simple logical rewiring --- there is no point in coding this as there are no bytes to swap in this implementation

            if (in_place_mixcolumn)
            {
                // Apply MixWord on the first byte in its entirety, as we act on the entire first word
                QAES.InPlace.MixWord(out_state, costing);
            }
            else
            {
                MaximovMixColumn.MixWord(out_state[0..31],out_state[32..63]);
                for i in 0..31
                {
                   REWIRE(out_state[i],out_state[32+i], costing);
                }
            }
            // Apply a slightly reduced AddRoundKey again 
            if (Nk == 4)
            {
                // AES128
                QAES.InPlace.KeyExpansion(key, round, Nk, 0, Nk-1, costing);
                // A slightly reduced AddRoundKey (negligible impact, but may as well optimise)
                for i in 0..31
                {
                    CNOT(key[0 + i], out_state[i]);
                }
            }
            elif (Nk == 6)
            {
                // AES192
                if (round % 3 == 1)
                {
                    // shallowest variant found so far (if used in combination with others key_round varinats)
                    let key_round = (round/3) * 2 + 1;
                    if (round > 1)
                    {
                        QAES.InPlace.KeyExpansion(key, key_round, Nk, 2*Nk/3, Nk-1, costing);
                    }
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, 1, costing);
                    for i in 0..31
                    {
                        CNOT(key[4*32 + i], out_state[i]);
                    }
                }
                elif (round % 3 == 2)
                {
                    let key_round = (round/3) * 2 + 1;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 2, Nk-1, costing);
                    for i in 0..31
                    {
                        CNOT(key[2*32 + 0*8 + i], out_state[i]);
                    }
                }
                else
                {
                    let key_round = (round/3) * 2;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, 2*Nk/3-1, costing);
                    for i in 0..31
                    {
                        CNOT(key[0*32 + 0*8 + i], out_state[i]);
                    }
                }
            }
            elif (Nk == 8)
            {
                // AES256
                if (round % 2 == 0)
                {
                    let key_round = round/2;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, Nk/2-1, costing);
                    for i in 0..31
                    {
                        CNOT(key[0*32 + 0*8 + i], out_state[i]);
                    }
                }
                else
                {
                    if (round > 2)
                    {
                        let key_round = round/2;
                        QAES.InPlace.KeyExpansion(key, key_round, Nk, Nk/2, Nk-1, costing);
                    }
                    for i in 0..31
                    {
                        CNOT(key[4*32 + 0*8 + i], out_state[i]);
                    }
                }
            }
        }
        adjoint auto;
    }

    // CustomFinalRound assumes that the input bytes are 0,1,2,3 of the original 0,..,15 of the full last round input
    // We have spare qubits at this stage, so we simply use ForwardSBox.
    // in_state  --- 32 bits  [32]
    // out_state --- 32 bits  [32] + auxiallary qubits (we don't worry about cleaning up the final round as all we care about is the test
    operation CustomFinalRound(in_state: Qubit[], out_state: Qubit[], key: Qubit[], round: Int, Nk : Int, costing: Bool) : Unit
    {
        body (...)
        {
            // Perform only 4 S-Boxes instead of 16 
            QAES.SubByte(in_state, out_state, costing);
            //QAES.SubByte(in_state, out_state, costing);
            // ShiftRows is a simple logical rewiring --- we consider a condensed output state of 4 bytes, so only need to reorder the ones in the wrong order
            REWIREBytes(out_state[8..15],out_state[24..31],costing);
            // No MixColumns operations in the final round

            // A slightly reduced AddRoundKey (negligible impact, but may as well optimise)
            if (Nk == 4)
            {
                // AES128
                // Nk == Nb, so can simply run a round of key expansion
                // for every round of AES
                QAES.InPlace.KeyExpansion(key, round, Nk, 0, Nk-1, costing);
                for i in 0..7
                {
                    CNOT(key[0*32 + 0*8 + i], out_state[0 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[1*32 + 3*8 + i], out_state[8 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[2*32 + 2*8 + i], out_state[16 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[3*32 + 1*8 + i], out_state[24 + i]);
                }
            }
            elif (Nk == 6)
            {
                // AES192
                let key_round = (round/3) * 2;
                // note, need only first 4 words of last key round
                QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, Nk-3, costing);
                for i in 0..7
                {
                    CNOT(key[0*32 + 0*8 + i], out_state[0 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[1*32 + 3*8 + i], out_state[8 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[2*32 + 2*8 + i], out_state[16 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[3*32 + 1*8 + i], out_state[24 + i]);
                }
            }
            elif (Nk == 8)
            {
                // AES256
                // note, need only first 4 words of last key round
                let key_round = round/2;
                QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, Nk/2-1, costing);
                for i in 0..7
                {
                    CNOT(key[0*32 + 0*8 + i], out_state[0 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[1*32 + 3*8 + i], out_state[8 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[2*32 + 2*8 + i], out_state[16 + i]);
                }
                for i in 0..7
                {
                    CNOT(key[3*32 + 1*8 + i], out_state[24 + i]);
                }
            }
            REWIREBytes(out_state[8..15],out_state[24..31],costing);


        }
        adjoint auto;
    }


    operation FinalRound(in_state: Qubit[][], out_state: Qubit[][], key: Qubit[], round: Int, Nk: Int, costing: Bool) : Unit
    {
        body (...)
        {
            QAES.ByteSub(in_state, out_state, costing);
            QAES.InPlace.ShiftRow(out_state, costing);
            if (Nk == 4)
            {
                // AES128
                // Nk == Nb, so can simply run a round of key expansion
                // for every round of AES
                QAES.InPlace.KeyExpansion(key, round, Nk, 0, Nk-1, costing);
                QAES.Widest.AddRoundKey(out_state, key);
            }
            elif (Nk == 6)
            {
                // AES192
                let key_round = (round/3) * 2;
                // note, need only first 4 words of last key round
                QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, Nk-3, costing);
                QAES.Widest.AddRoundKey(out_state, key[0*32..(4*32-1)]);
            }
            elif (Nk == 8)
            {
                // AES256
                // note, need only first 4 words of last key round
                let key_round = round/2;
                QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, Nk/2-1, costing);
                QAES.Widest.AddRoundKey(out_state, key[0*32..(4*32-1)]);
            }
        }
        adjoint auto;
    }



    operation CustomForwardRijndael(key: Qubit[], state: Qubit[], Nr: Int, Nk: Int, in_place_mixcolumn : Bool, costing: Bool) : Unit
    {
        body (...)
        {
            // Message("Regular rounds starting");
            // Message("");
            // "round 0"
            QAES.Widest.AddRoundKey([
                state[(0*32)..(1*32-1)],
                state[(1*32)..(2*32-1)],
                state[(2*32)..(3*32-1)],
                state[(3*32)..(4*32-1)]
            ], key);

        
            for i in 1..(Nr-3)
            {
                // round i \in [1..Nr-1]
                QAES.SmartWide.Round(in_place_mixcolumn ? [
                    state[(4*32*(i-1) + 0*32)..(4*32*(i-1) + 1*32 - 1)],
                    state[(4*32*(i-1) + 1*32)..(4*32*(i-1) + 2*32 - 1)],
                    state[(4*32*(i-1) + 2*32)..(4*32*(i-1) + 3*32 - 1)],
                    state[(4*32*(i-1) + 3*32)..(4*32*(i-1) + 4*32 - 1)]
                ] | [
                    state[(8*32*(i-1) + 0*32)..(8*32*(i-1) + 1*32 - 1)],
                    state[(8*32*(i-1) + 1*32)..(8*32*(i-1) + 2*32 - 1)],
                    state[(8*32*(i-1) + 2*32)..(8*32*(i-1) + 3*32 - 1)],
                    state[(8*32*(i-1) + 3*32)..(8*32*(i-1) + 4*32 - 1)]
                ], in_place_mixcolumn ? [
                    state[(4*32*i + 0*32)..(4*32*i + 1*32 - 1)],
                    state[(4*32*i + 1*32)..(4*32*i + 2*32 - 1)],
                    state[(4*32*i + 2*32)..(4*32*i + 3*32 - 1)],
                    state[(4*32*i + 3*32)..(4*32*i + 4*32 - 1)]
                ] | [
                    state[(8*32*(i-1) +  4*32)..(8*32*(i-1) +  5*32 - 1)],
                    state[(8*32*(i-1) +  5*32)..(8*32*(i-1) +  6*32 - 1)],
                    state[(8*32*(i-1) +  6*32)..(8*32*(i-1) +  7*32 - 1)],
                    state[(8*32*(i-1) +  7*32)..(8*32*(i-1) +  8*32 - 1)],
                    state[(8*32*(i-1) +  8*32)..(8*32*(i-1) +  9*32 - 1)],
                    state[(8*32*(i-1) +  9*32)..(8*32*(i-1) + 10*32 - 1)],
                    state[(8*32*(i-1) + 10*32)..(8*32*(i-1) + 11*32 - 1)],
                    state[(8*32*(i-1) + 11*32)..(8*32*(i-1) + 12*32 - 1)]
                ], key, i, Nk, in_place_mixcolumn, costing);
            }

            if (in_place_mixcolumn)
                {
                // Message("Regular rounds completed");
                // Message("");
                // Message($"{4*32*(Nr-2-1)}");
                // Message($"{4*32*(Nr-2)   + 4*32}");
                // Message($"{Length(state)}");
                // Message($"{Length(key)}");
                // Message("");
                // Message("AntepenultimateRound running");
                AntePenultimateRound([
                        state[(4*32*(Nr - 2-1) + 0*32)..(4*32*(Nr - 2-1) + 1*32 - 1)],
                        state[(4*32*(Nr - 2-1) + 1*32)..(4*32*(Nr - 2-1) + 2*32 - 1)],
                        state[(4*32*(Nr - 2-1) + 2*32)..(4*32*(Nr - 2-1) + 3*32 - 1)],
                        state[(4*32*(Nr - 2-1) + 3*32)..(4*32*(Nr - 2-1) + 4*32 - 1)]
                    ] 
                    ,
                    [
                        state[(4*32*(Nr - 2) + 0*32)..(4*32*(Nr - 2) + 1*32 - 1)],
                        state[(4*32*(Nr - 2) + 1*32)..(4*32*(Nr - 2) + 2*32 - 1)],
                        state[(4*32*(Nr - 2) + 2*32)..(4*32*(Nr - 2) + 3*32 - 1)],
                        state[(4*32*(Nr - 2) + 3*32)..(4*32*(Nr - 2) + 4*32 - 1)]
                    ] 
                    , 
                    key, Nr - 2, Nk, costing);
                // Message("AntepenultimateRound completed");

                // Message($"{4*32*(Nr-1-1)}");
                // Message($"{4*32*(Nr-1)   + 1*32}");
                // Message($"{Length(state)}");
                // Message($"{Length(key)}");
                // Message("");
                // Message("PenultimateRound running");
                // Penultimate Round 
                PenultimateRound(
                        state[(4*32*((Nr - 1)-1) + 0*32)..(4*32*((Nr - 1)-1) + 0*32 + 7)] + 
                        state[(4*32*((Nr - 1)-1) + 1*32)..(4*32*((Nr - 1)-1) + 1*32 + 7)] + 
                        state[(4*32*((Nr - 1)-1) + 2*32)..(4*32*((Nr - 1)-1) + 2*32 + 7)] +  
                        state[(4*32*((Nr - 1)-1) + 3*32)..(4*32*((Nr - 1)-1) + 3*32 + 7)]
                    ,
                        state[(4*32*(Nr - 1) + 0*32)..(4*32*(Nr - 1) + 1*32 - 1)]
                    //   state[(4*32*i + 1*32)..(4*32*i + 2*32 - 1)],
                    //   state[(4*32*i + 2*32)..(4*32*i + 3*32 - 1)],
                    //   state[(4*32*i + 3*32)..(4*32*i + 4*32 - 1)]
                    //] 
                    , 
                    key, Nr-1, Nk, in_place_mixcolumn, costing);
                // Message("PenultimateRound completed");
                // Message("");
                // Message("CustomFinalRound running");
                // Message($"{4*32*(Nr-1)}");
                // Message($"{4*32*(Nr-1)   + 2*32}");
                // Message($"{Length(state)}");
                // Message($"{Length(key)}");           
                CustomFinalRound(state[(4*32*(Nr-1) + 0*32)..(4*32*(Nr-1) + 1*32 - 1)], state[(4*32*(Nr-1) + 1*32)..(4*32*(Nr-1) + 2*32 - 1)],
                    key, Nr, Nk, costing);
                // Message("CustomFinalRound Completed");
            }
            else
            {
                AntePenultimateRound([
                        state[(8*32*(Nr-4) +  8*32)..(8*32*(Nr-4) +  9*32 - 1)],
                        state[(8*32*(Nr-4) +  9*32)..(8*32*(Nr-4) + 10*32 - 1)],
                        state[(8*32*(Nr-4) + 10*32)..(8*32*(Nr-4) + 11*32 - 1)],
                        state[(8*32*(Nr-4) + 11*32)..(8*32*(Nr-4) + 12*32 - 1)]
                    ] 
                    ,
                    [
                        state[(8*32*(Nr-4) +  12*32)..(8*32*(Nr-4) +  13*32 - 1)],
                        state[(8*32*(Nr-4) +  13*32)..(8*32*(Nr-4) + 14*32 - 1)],
                        state[(8*32*(Nr-4) + 14*32 )..(8*32*(Nr-4) + 15*32 - 1)],
                        state[(8*32*(Nr-4) + 15*32 )..(8*32*(Nr-4) + 16*32 - 1)]
                    ] 
                    , 
                    key, Nr - 2, Nk, costing);


                    PenultimateRound(
                        state[(8*32*(Nr-4) +  12*32)..(8*32*(Nr-4) +  12*32 +7)] +
                        state[(8*32*(Nr-4) +  13*32)..(8*32*(Nr-4) +  13*32 +7)] +
                        state[(8*32*(Nr-4) + 14*32 )..(8*32*(Nr-4) +  14*32 +7)] +
                        state[(8*32*(Nr-4) + 15*32 )..(8*32*(Nr-4) +  15*32 +7)]
                    ,
                        state[(8*32*(Nr-4) + 16*32 )..(8*32*(Nr-4) + 17*32 - 1)] +
                        state[(8*32*(Nr-4) + 17*32 )..(8*32*(Nr-4) + 18*32 - 1)]
                    //   state[(4*32*i + 1*32)..(4*32*i + 2*32 - 1)],
                    //   state[(4*32*i + 2*32)..(4*32*i + 3*32 - 1)],
                    //   state[(4*32*i + 3*32)..(4*32*i + 4*32 - 1)]
                    //] 
                    , 
                    key, Nr-1, Nk, in_place_mixcolumn, costing);

                    CustomFinalRound(state[(8*32*(Nr-4) + 16*32 )..(8*32*(Nr-4) + 17*32 - 1)], state[(8*32*(Nr-4) + 18*32 )..(8*32*(Nr-4) + 19*32 - 1)],
                    key, Nr, Nk, costing);
            }
        }
        adjoint auto;
    }

    operation CheapGroverOracle(key_register : Qubit[], success: Qubit, plaintext : Bool[], ciphertext : Bool[], Nr : Int, Nk : Int, in_place_mixcolumn : Bool, costing : Bool) : Unit
    {
        let test_ciphertext_bits = ciphertext[0..7] + 
        ciphertext[(1*32 + 3*8)..(1*32 + 4*8 - 1)] + 
        ciphertext[(2*32 + 2*8)..(2*32 + 3*8 - 1)] + 
        ciphertext[(3*32 + 1*8)..(3*32 + 2*8 - 1)];

        use state_register  =  Qubit[in_place_mixcolumn ? (Nr-1)*128 + 64 | 8*32*(Nr-4) + 19*32]
        {

            // Load the plaintext (can be assumed to be preloaded in actual case)
            for i in 0..127
            {
                Set(BoolAsResult(plaintext[i]),state_register[i]);
            }

            CustomForwardRijndael(key_register,state_register, Nr, Nk, in_place_mixcolumn, costing);
            //ZCompareQubitstring(state_register[(4*32*(Nr-1) + 1*32)..(4*32*(Nr-1) + 2*32 - 1)], test_ciphertext_bits, costing);

            if (in_place_mixcolumn)
            {
                CompareQubitstring(success,state_register[(4*32*(Nr-1) + 1*32)..(4*32*(Nr-1) + 2*32 - 1)], test_ciphertext_bits, costing);
            }
            else
            {
                CompareQubitstring(success,state_register[(8*32*(Nr-4) + 18*32 )..(8*32*(Nr-4) + 19*32 - 1)], test_ciphertext_bits, costing);
            }
            Adjoint CustomForwardRijndael(key_register,state_register, Nr, Nk, in_place_mixcolumn, costing);


            // Unload the plaintext (can be assumed to be preloaded in actual case)
            for i in 0..127
            {
                Set(BoolAsResult(plaintext[i]),state_register[i]);
            }
            
        }
    }

    operation SerialGroverOracle(key_register : Qubit[], success : Qubit, plaintext : Bool[][], ciphertext : Bool[][], Nr : Int, Nk : Int, in_place_mixcolumn : Bool ,costing : Bool) : Unit
    {
        let r = Length(plaintext);

        use (state_register, success_register)  =  (Qubit[in_place_mixcolumn ? ((Nr+1)*128) | (8*32*(Nr-1) + 8*32)], Qubit[r-1])
        {

            // Compute all but the last success flag
            for i in 0..(r-2)
            {
                // Load the relevant plaintexts (first plaintext can be assumed to be preloaded in actual use case)
                if (i == 0)
                {
                    for j in 0..127
                    {
                        if (plaintext[i][j])
                        { 
                            X(state_register[j]);
                        }
                    }
                }
                else
                {
                    for j in 0..127
                    {
                        if (Xor(plaintext[i-1][j],plaintext[i][j]))
                        {
                            X(state_register[j]);
                        }
                    }
                }
                // Write out the computed ciphertext
                QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, in_place_mixcolumn, costing);

                // Write out a single-qubit flag  if we have a match with the ciphertext 
                if (in_place_mixcolumn)
                {
                    CompareQubitstring(success_register[i], state_register[((Nr)*128)..((Nr+1)*128 -1)], ciphertext[i], costing);
                }
                else
                {
                    CompareQubitstring(success_register[i], state_register[((8*32*(Nr-1) + 8*32) -128 )..((8*32*(Nr-1) + 8*32) -1 )], ciphertext[i], costing);
                }

                // Uncompute everything but the flags
                Adjoint QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, in_place_mixcolumn, costing);
            }

            // Process the final plaintext
            for j in 0..127
                {
                    if (Xor(plaintext[r-2][j],plaintext[r-1][j]))
                    {
                        X(state_register[j]);
                    }
                }
            // Write out the final computed ciphertext
            QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, in_place_mixcolumn, costing);

            // Invert if all previous flags are 1 and the last ciphertext matches 
            mutable comparison_bitstring = ciphertext[r-1];
            for i in 0..r-2
            {
                set comparison_bitstring += [true];
            }
            CompareQubitstring(success, state_register[((Nr)*128)..((Nr+1)*128 -1)] + success_register, comparison_bitstring, costing);


            // Clean up the final computed ciphertext
            Adjoint QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, in_place_mixcolumn, costing);


            //
            // Clean up the success flags and ancilla qubits

            // Compute all but the last success flag
            for i in (r-2)..-1..0
            {
                // Load the relevant plaintext
                if (i == 0)
                {
                    for j in 0..127
                    {
                        if (Xor(plaintext[0][j],plaintext[1][j]))
                        {
                            X(state_register[j]);
                        }
                    }
                }
                else
                {
                    for j in 0..127
                    {
                        if (Xor(plaintext[i][j],plaintext[i+1][j]))
                        {
                            X(state_register[j]);
                        }
                    }
                }
                // Write out the computed ciphertext
                QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, in_place_mixcolumn, costing);

                // Write out a single-qubit flag  if we have a match with the ciphertext
                CompareQubitstring(success_register[i], state_register[((Nr)*128)..((Nr+1)*128 -1)], ciphertext[i], costing);
                
                // Uncompute everything but the flags
                Adjoint QAES.SmartWide.ForwardRijndael(key_register, state_register, Nr, Nk, in_place_mixcolumn, costing);
            }

            for j in 0..127
            {
                if (plaintext[0][j])
                { 
                    X(state_register[j]);
                }
            }
        }
    }

    operation ExpensiveSerialGroverOracle(key_register : Qubit[], success : Qubit, plaintext : Bool[][], ciphertext : Bool[][], Nr : Int, Nk : Int, costing : Bool) : Unit
    {
        let r = Length(plaintext);

        use (state_register, success_register)  =  (Qubit[128+(Nr-3)*128], Qubit[r-1])
        {

            // Compute all but the last success flag
            for i in 0..(r-2)
            {
                // Load the relevant plaintexts (first plaintext can be assumed to be preloaded in actual use case)
                if (i == 0)
                {
                    for j in 0..127
                    {
                        if (plaintext[i][j])
                        { 
                            X(state_register[j]);
                        }
                    }
                }
                else
                {
                    for j in 0..127
                    {
                        if (Xor(plaintext[i-1][j],plaintext[i][j]))
                        {
                            X(state_register[j]);
                        }
                    }
                }
                // Write out the computed ciphertext
                ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, costing);

                // Write out a single-qubit flag  if we have a match with the ciphertext 
                CompareQubitstring(success_register[i], state_register[(128 + 4*32*(Nr-4) + 0*32)..(128 + 4*32*(Nr-4) + 127)], ciphertext[i], costing);
                
                // Uncompute everything but the flags
                Adjoint ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, costing);
            }

            // Process the final plaintext
            for j in 0..127
                {
                    if (Xor(plaintext[r-2][j],plaintext[r-1][j]))
                    {
                        X(state_register[j]);
                    }
                }
            // Write out the final computed ciphertext
            ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, costing);

            // Invert if all previous flags are 1 and the last ciphertext matches 
            mutable comparison_bitstring = ciphertext[r-1];
            for i in 0..r-2
            {
                set comparison_bitstring += [true];
            }
            CompareQubitstring(success, state_register[(128 + 4*32*(Nr-4) + 0*32)..(128 + 4*32*(Nr-4) + 127)] + success_register, comparison_bitstring, costing);


            // Clean up the final computed ciphertext
            Adjoint ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, costing);


            //
            // Clean up the success flags and ancilla qubits

            // Compute all but the last success flag
            for i in (r-2)..-1..0
            {
                // Load the relevant plaintext
                if (i == 0)
                {
                    for j in 0..127
                    {
                        if (Xor(plaintext[0][j],plaintext[1][j]))
                        {
                            X(state_register[j]);
                        }
                    }
                }
                else
                {
                    for j in 0..127
                    {
                        if (Xor(plaintext[i][j],plaintext[i+1][j]))
                        {
                            X(state_register[j]);
                        }
                    }
                }
                // Write out the computed ciphertext
                ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, costing);

                // Write out a single-qubit flag  if we have a match with the ciphertext
                CompareQubitstring(success_register[i], state_register[(128 + 4*32*(Nr-4) + 0*32)..(128 + 4*32*(Nr-4) + 127)], ciphertext[i], costing);
                
                // Uncompute everything but the flags
                Adjoint ExpensiveForwardRijndael(key_register, state_register, Nr, Nk, costing);
            }

            for j in 0..127
            {
                if (plaintext[0][j])
                { 
                    X(state_register[j]);
                }
            }
        }
    }



    // A simple function to invert the phase of a computational basis state if it equals a classically known bitstring. Saves a qubit.
    operation ZCompareQubitstring(register : Qubit[], bitstring : Bool[], costing : Bool) : Unit
    {
        let l = Length(bitstring);
        for i in 0..(l-1)
        {
            if (bitstring[i] == false)
            {
                X(register[i]);
            }
        }

        InvertAllOnes(register, costing);
        
        for i in 0..(l-1)
        {
            if (bitstring[i] == false)
            {
                X(register[i]);
            }
        }
    }

    // A simple function to invert the phase of a computational basis state if all qubits are |1>. Saves one qubit compared to naively writing out multiply controlled X to another qubit
    operation InvertAllOnes(register : Qubit[], costing : Bool) : Unit
    {
        H(register[0]);
        TestIfAllOnes(register[1..(Length(register)-1)], register[0], costing);
        H(register[0]);
    }



    // A simple modification that saves a few qubits by uncomputing early on.
    operation ExpensiveForwardRijndael(key: Qubit[], state: Qubit[], Nr: Int, Nk: Int, costing: Bool) : Unit
    {
        body (...)
        {
            // "round 0"
            QAES.Widest.AddRoundKey([
                state[(0*32)..(1*32-1)],
                state[(1*32)..(2*32-1)],
                state[(2*32)..(3*32-1)],
                state[(3*32)..(4*32-1)]
            ], key);

            for i in 1..4
            {
                // round i \in [1..Nr-1]
                QAES.SmartWide.Round([
                    state[(4*32*(i-1) + 0*32)..(4*32*(i-1) + 1*32 - 1)],
                    state[(4*32*(i-1) + 1*32)..(4*32*(i-1) + 2*32 - 1)],
                    state[(4*32*(i-1) + 2*32)..(4*32*(i-1) + 3*32 - 1)],
                    state[(4*32*(i-1) + 3*32)..(4*32*(i-1) + 4*32 - 1)]
                ],[
                    state[(4*32*i + 0*32)..(4*32*i + 1*32 - 1)],
                    state[(4*32*i + 1*32)..(4*32*i + 2*32 - 1)],
                    state[(4*32*i + 2*32)..(4*32*i + 3*32 - 1)],
                    state[(4*32*i + 3*32)..(4*32*i + 4*32 - 1)]
                ], key, i, Nk, true, costing);
            }
            use temp_register = Qubit[128]
            {
                for j in 0..127
                {
                    CNOT(state[4*32*4 + j], temp_register[j]);
                }

            for i in 4..-1..1
            {
                // round i \in [1..Nr-1]
                Adjoint QAES.SmartWide.Round([
                    state[(4*32*(i-1) + 0*32)..(4*32*(i-1) + 1*32 - 1)],
                    state[(4*32*(i-1) + 1*32)..(4*32*(i-1) + 2*32 - 1)],
                    state[(4*32*(i-1) + 2*32)..(4*32*(i-1) + 3*32 - 1)],
                    state[(4*32*(i-1) + 3*32)..(4*32*(i-1) + 4*32 - 1)]
                ],[
                    state[(4*32*i + 0*32)..(4*32*i + 1*32 - 1)],
                    state[(4*32*i + 1*32)..(4*32*i + 2*32 - 1)],
                    state[(4*32*i + 2*32)..(4*32*i + 3*32 - 1)],
                    state[(4*32*i + 3*32)..(4*32*i + 4*32 - 1)]
                ], key, i, Nk, true, costing);
            }

            for j in 0..127
            {
                REWIRE(temp_register[j], state[128 + j], costing);
            }

            }

            for i in 1..4
            {
                RoundKeyExpansionOnly(key,i, Nk, true, costing);
            }

            for i in 1..(Nr-1-4)
            {
                // round i \in [1..Nr-1]
                QAES.SmartWide.Round([
                    state[(128 + 4*32*((i)-1) + 0*32)..(128 + 4*32*((i)-1) + 1*32 - 1)],
                    state[(128 + 4*32*((i)-1) + 1*32)..(128 + 4*32*((i)-1) + 2*32 - 1)],
                    state[(128 + 4*32*((i)-1) + 2*32)..(128 + 4*32*((i)-1) + 3*32 - 1)],
                    state[(128 + 4*32*((i)-1) + 3*32)..(128 + 4*32*((i)-1) + 4*32 - 1)]
                ],[
                    state[(128 + 4*32*(i) + 0*32)..(128 + 4*32*(i) + 1*32 - 1)],
                    state[(128 + 4*32*(i) + 1*32)..(128 + 4*32*(i) + 2*32 - 1)],
                    state[(128 + 4*32*(i) + 2*32)..(128 + 4*32*(i) + 3*32 - 1)],
                    state[(128 + 4*32*(i) + 3*32)..(128 + 4*32*(i) + 4*32 - 1)]
                ], key, i+4, Nk, true, costing);
            }

            // final round

            FinalRound([
                    state[(128 + 4*32*((Nr-4)-1) + 0*32)..(128 + 4*32*((Nr-4)-1) + 1*32 - 1)],
                    state[(128 + 4*32*((Nr-4)-1) + 1*32)..(128 + 4*32*((Nr-4)-1) + 2*32 - 1)],
                    state[(128 + 4*32*((Nr-4)-1) + 2*32)..(128 + 4*32*((Nr-4)-1) + 3*32 - 1)],
                    state[(128 + 4*32*((Nr-4)-1) + 3*32)..(128 + 4*32*((Nr-4)-1) + 4*32 - 1)]
                ], [
                    state[(128 + 4*32*(Nr-4) + 0*32)..(128 + 4*32*(Nr-4) + 1*32 - 1)],
                    state[(128 + 4*32*(Nr-4) + 1*32)..(128 + 4*32*(Nr-4) + 2*32 - 1)],
                    state[(128 + 4*32*(Nr-4) + 2*32)..(128 + 4*32*(Nr-4) + 3*32 - 1)],
                    state[(128 + 4*32*(Nr-4) + 3*32)..(128 + 4*32*(Nr-4) + 4*32 - 1)]
                ],
                key, Nr, Nk, costing
            );
        }
        adjoint auto;
    }


    // round values start from 1 to Nr-1, since the final round Nr has a different shape
    operation RoundKeyExpansionOnly(key: Qubit[], round: Int, Nk: Int, in_place_mixcolumn: Bool, costing: Bool) : Unit
    {
        body (...)
        {
            if (Nk == 4)
            {
                // AES128
                QAES.InPlace.KeyExpansion(key, round, Nk, 0, Nk-1, costing);
            }
            elif (Nk == 6)
            {
                // AES192
                if (round % 3 == 1)
                {
                    // shallowest variant found so far (if used in combination with others key_round varinats)
                    let key_round = (round/3) * 2 + 1;
                    if (round > 1)
                    {
                        QAES.InPlace.KeyExpansion(key, key_round, Nk, 2*Nk/3, Nk-1, costing);
                    }
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, 1, costing);

                }
                elif (round % 3 == 2)
                {
                    let key_round = (round/3) * 2 + 1;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 2, Nk-1, costing);
                }
                else
                {
                    let key_round = (round/3) * 2;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, 2*Nk/3-1, costing);
                }
            }
            elif (Nk == 8)
            {
                // AES256
                if (round % 2 == 0)
                {
                    let key_round = round/2;
                    QAES.InPlace.KeyExpansion(key, key_round, Nk, 0, Nk/2-1, costing);
                }
                else
                {
                    if (round > 2)
                    {
                        let key_round = round/2;
                        QAES.InPlace.KeyExpansion(key, key_round, Nk, Nk/2, Nk-1, costing);
                    }
                }
            }
        }
        adjoint auto;
    }

}