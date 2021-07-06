// Creation of modified MixColumns that output individual byters

namespace MixColumnAddon
{
    open Microsoft.Quantum.Intrinsic;
    open QUtilities;

    operation MixByteIn (x: Qubit[], output_byte : Int, free_swaps : Bool) : Unit
    {
        // x: input  --- 32 bits
        // output_byte --- which of the bytes we want to output to the first 8 bits of the input state
        // free_swap   --- allows free swap operations ala microsoft grover-blocks code

        // Simply uses the outputs as an xor sum and outputs on the first 8 bits of the wire via free logical swapping operations
        // Based off code which computes the xor equations required for each invidual bit, then identifies the unique bit which shares no identical variable with any of the other 
        // equations for the other 7 output wires. This bit is then written to (which means that we do not have to add this bit) and the logical rewiring then occurs.
        body (...)
        {
            if (output_byte == 1)
            {
                CNOT(x[7],x[16]);
                CNOT(x[15],x[17]);
                CNOT(x[1],x[18]);
                CNOT(x[2],x[19]);
                CNOT(x[3],x[20]);
                CNOT(x[4],x[21]);
                CNOT(x[5],x[22]);
                CNOT(x[15],x[23]);

                CNOT(x[8],x[16]);
                CNOT(x[7],x[17]);
                CNOT(x[9],x[18]);
                CNOT(x[10],x[19]);
                CNOT(x[11],x[20]);
                CNOT(x[12],x[21]);
                CNOT(x[13],x[22]);
                CNOT(x[14],x[23]);

                CNOT(x[15],x[16]);
                CNOT(x[8],x[17]);
                CNOT(x[10],x[18]);
                CNOT(x[11],x[19]);
                CNOT(x[7],x[20]);
                CNOT(x[13],x[21]);
                CNOT(x[30],x[22]);
                CNOT(x[31],x[23]);

                CNOT(x[24],x[16]);
                CNOT(x[25],x[17]);
                CNOT(x[26],x[18]);
                CNOT(x[15],x[19]);
                CNOT(x[12],x[20]);
                CNOT(x[29],x[21]);
                CNOT(x[14],x[22]);
                CNOT(x[6],x[23]);

                CNOT(x[9],x[17]);
                CNOT(x[0],x[17]);
                CNOT(x[7],x[19]);
                CNOT(x[27],x[19]);
                CNOT(x[15],x[20]);
                CNOT(x[28],x[20]);

                REWIRE(x[0],x[16],free_swaps);
                REWIRE(x[1],x[17],free_swaps);
                REWIRE(x[2],x[18],free_swaps);
                REWIRE(x[3],x[19],free_swaps);
                REWIRE(x[4],x[20],free_swaps);
                REWIRE(x[5],x[21],free_swaps);
                REWIRE(x[6],x[22],free_swaps);
                REWIRE(x[7],x[23],free_swaps);
            }
            elif (output_byte == 2)
            {

                CNOT(x[15],x[0]);
                CNOT(x[8],x[1]);
                CNOT(x[9],x[2]);
                CNOT(x[10],x[3]);
                CNOT(x[11],x[4]);
                CNOT(x[12],x[5]);
                CNOT(x[22],x[6]);
                CNOT(x[31],x[7]);

                CNOT(x[16],x[0]);
                CNOT(x[23],x[1]);
                CNOT(x[17],x[2]);
                CNOT(x[15],x[3]);
                CNOT(x[19],x[4]);
                CNOT(x[20],x[5]);
                CNOT(x[30],x[6]);
                CNOT(x[23],x[7]);

                CNOT(x[23],x[0]);
                CNOT(x[15],x[1]);
                CNOT(x[18],x[2]);
                CNOT(x[27],x[3]);
                CNOT(x[20],x[4]);
                CNOT(x[21],x[5]);
                CNOT(x[13],x[6]);
                CNOT(x[22],x[7]);

                CNOT(x[24],x[0]);
                CNOT(x[17],x[1]);
                CNOT(x[26],x[2]);
                CNOT(x[18],x[3]);
                CNOT(x[15],x[4]);
                CNOT(x[29],x[5]);
                CNOT(x[21],x[6]);
                CNOT(x[14],x[7]);

                CNOT(x[16],x[1]);
                CNOT(x[25],x[1]);
                CNOT(x[23],x[3]);
                CNOT(x[19],x[3]);
                CNOT(x[28],x[4]);
                CNOT(x[23],x[4]);
 
            }
            elif (output_byte == 3)
            {
                
                CNOT(x[8],x[0]);
                CNOT(x[9],x[1]);
                CNOT(x[10],x[2]);
                CNOT(x[11],x[3]);
                CNOT(x[12],x[4]);
                CNOT(x[13],x[5]);
                CNOT(x[14],x[6]);
                CNOT(x[15],x[7]);

                CNOT(x[23],x[0]);
                CNOT(x[16],x[1]);
                CNOT(x[17],x[2]);
                CNOT(x[18],x[3]);
                CNOT(x[31],x[4]);
                CNOT(x[20],x[5]);
                CNOT(x[21],x[6]);
                CNOT(x[22],x[7]);

                CNOT(x[24],x[0]);
                CNOT(x[23],x[1]);
                CNOT(x[25],x[2]);
                CNOT(x[31],x[3]);
                CNOT(x[27],x[4]);
                CNOT(x[28],x[5]);
                CNOT(x[29],x[6]);
                CNOT(x[30],x[7]);

                CNOT(x[31],x[0]);
                CNOT(x[24],x[1]);
                CNOT(x[26],x[2]);
                CNOT(x[23],x[3]);
                CNOT(x[28],x[4]);
                CNOT(x[29],x[5]);
                CNOT(x[30],x[6]);
                CNOT(x[31],x[7]);

                CNOT(x[25],x[1]);
                CNOT(x[31],x[1]);
                CNOT(x[27],x[3]);
                CNOT(x[26],x[3]);
                CNOT(x[19],x[4]);
                CNOT(x[23],x[4]);
            }
            elif (output_byte == 4){

                CNOT(x[7],x[8]);
                CNOT(x[0],x[9]);
                CNOT(x[1],x[10]);
                CNOT(x[2],x[11]);
                CNOT(x[3],x[12]);
                CNOT(x[4],x[13]);
                CNOT(x[5],x[14]);
                CNOT(x[6],x[15]);

                CNOT(x[0],x[8]);
                CNOT(x[1],x[9]);
                CNOT(x[2],x[10]);
                CNOT(x[31],x[11]);
                CNOT(x[4],x[12]);
                CNOT(x[5],x[13]);
                CNOT(x[6],x[14]);
                CNOT(x[7],x[15]);

                CNOT(x[16],x[8]);
                CNOT(x[31],x[9]);
                CNOT(x[18],x[10]);
                CNOT(x[19],x[11]);
                CNOT(x[7],x[12]);
                CNOT(x[21],x[13]);
                CNOT(x[22],x[14]);
                CNOT(x[23],x[15]);

                CNOT(x[31],x[8]);
                CNOT(x[17],x[9]);
                CNOT(x[25],x[10]);
                CNOT(x[7],x[11]);
                CNOT(x[20],x[12]);
                CNOT(x[28],x[13]);
                CNOT(x[29],x[14]);
                CNOT(x[30],x[15]);

                CNOT(x[7],x[9]);
                CNOT(x[26],x[11]);
                CNOT(x[27],x[12]);
                CNOT(x[24],x[9]);
                CNOT(x[3],x[11]);
                CNOT(x[31],x[12]);

                REWIRE(x[0],x[8],free_swaps);
                REWIRE(x[1],x[9],free_swaps);
                REWIRE(x[2],x[10],free_swaps);
                REWIRE(x[3],x[11],free_swaps);
                REWIRE(x[4],x[12],free_swaps);
                REWIRE(x[5],x[13],free_swaps);
                REWIRE(x[6],x[14],free_swaps);
                REWIRE(x[7],x[15],free_swaps);
            }
        }
        adjoint auto;
    }
}