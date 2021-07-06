// NOTE: NEED TO INSTALL FILEHELPERS 
// Linux command (in project directory) "dotnet add package FileHelpers --version 3.4.2" 
// Taken as-is from "https://github.com/sam-jaques/offline-quantum-period-finding/"
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Library that deals with making human-friendly the CSV tracer's output
namespace CommaSeparated
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using FileHelpers; // csv parsing
    using Microsoft.Quantum.Simulation.Simulators.QCTraceSimulators;

    public class DisplayCSV
    {
        public static void Depth(string csv, string line_name, bool all = false)
        {
            var engine = new FileHelperAsyncEngine<DepthCounterCSV>();
            using (engine.BeginReadString(csv))
            {
                // This wont display anything, we have dropped it
                foreach (var err in engine.ErrorManager.Errors)
                {
                    Console.WriteLine();
                    Console.WriteLine("Error on Line number: {0}", err.LineNumber);
                    Console.WriteLine("Record causing the problem: {0}", err.RecordString);
                    Console.WriteLine("Complete exception information: {0}", err.ExceptionInfo.ToString());
                }

                // The engine is IEnumerable
                foreach (DepthCounterCSV cust in engine)
                {
                    // your code here
                    if (cust.Name == line_name || all)
                    {
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") depth avg " + cust.DepthAverage + " (variance " + cust.DepthVariance + ")");
                    }
                }
            }
        }

        public static void Width(string csv, string line_name, bool all = false)
        {
            var engine = new FileHelperAsyncEngine<WidthCounterCSV>();
            using (engine.BeginReadString(csv))
            {
                // This wont display anything, we have dropped it
                foreach (var err in engine.ErrorManager.Errors)
                {
                    Console.WriteLine();
                    Console.WriteLine("Error on Line number: {0}", err.LineNumber);
                    Console.WriteLine("Record causing the problem: {0}", err.RecordString);
                    Console.WriteLine("Complete exception information: {0}", err.ExceptionInfo.ToString());
                }

                // The engine is IEnumerable
                foreach (WidthCounterCSV cust in engine)
                {
                    // your code here
                    if (cust.Name == line_name || all)
                    {
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") initial width avg " + cust.InputWidthAverage + " (variance " + cust.InputWidthVariance + ")");
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") extra width avg " + cust.ExtraWidthAverage + " (variance " + cust.ExtraWidthVariance + ")");
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") return width avg " + cust.ReturnWidthAverage + " (variance " + cust.ReturnWidthVariance + ")");
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") borrowed width avg " + cust.BorrowedWidthAverage + " (variance " + cust.BorrowedWidthVariance + ")");
                    }
                }
            }
        }

        public static void Operations(string csv, string line_name, bool all = false)
        {
            var engine = new FileHelperAsyncEngine<OperationCounterCSV>();
            using (engine.BeginReadString(csv))
            {
                // This wont display anything, we have dropped it
                foreach (var err in engine.ErrorManager.Errors)
                {
                    Console.WriteLine();
                    Console.WriteLine("Error on Line number: {0}", err.LineNumber);
                    Console.WriteLine("Record causing the problem: {0}", err.RecordString);
                    Console.WriteLine("Complete exception information: {0}", err.ExceptionInfo.ToString());
                }

                // The engine is IEnumerable
                foreach (OperationCounterCSV cust in engine)
                {
                    // your code here
                    if (cust.Name == line_name || all)
                    {
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") CNOT count avg " + cust.CNOTAverage + " (variance " + cust.CNOTVariance + ")");
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") Clifford count avg " + cust.QubitCliffordAverage + " (variance " + cust.QubitCliffordVariance + ")");
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") T count avg " + cust.TAverage + " (variance " + cust.TVariance + ")");
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") R count avg " + cust.RAverage + " (variance " + cust.RVariance + ")");
                        Console.WriteLine(cust.Name + " (<- " + cust.Caller + ") Measure count avg " + cust.MeasureAverage + " (variance " + cust.MeasureVariance + ")");
                    }
                }
            }
        }

        public static void All(Dictionary<string, string> csv, string line_name, bool all = false)
        {
            // print results
            Depth(csv[MetricsCountersNames.depthCounter], line_name, all);
            Console.WriteLine();
            Width(csv[MetricsCountersNames.widthCounter], line_name, all);
            Console.WriteLine();
            Operations(csv[MetricsCountersNames.primitiveOperationsCounter], line_name, all);
            Console.WriteLine();
        }

        public static string GetHeader(bool fullDepth = false) 
        {
            string results = "operation,CNOT count,1-qubit clifford count,t count,r count,m count,";
            if (fullDepth) {
                results += "full depth,";
            } else {
                results += "t depth,";
            }
            results += "full width,max width,initial width,extra width,comment";
            return results;
        }

        public static string CSV(Dictionary<string, string> csv, string line_name, bool display_header = false, string comment = "", bool all = false, string suffix = "")
        {
            string results = string.Empty;

            results += $"{Environment.NewLine}{line_name}{suffix}, ";
            var countEngine = new FileHelperAsyncEngine<OperationCounterCSV>();
            using (countEngine.BeginReadString(csv[MetricsCountersNames.primitiveOperationsCounter]))
            {
                // The engine is IEnumerable
                foreach (OperationCounterCSV cust in countEngine)
                {
                    if (cust.Name == line_name || all)
                    {
                        results += $"{cust.CNOTAverage},{cust.QubitCliffordAverage},{cust.TAverage},{cust.RAverage},{cust.MeasureAverage},";
                    }
                }
            }

            var depthEngine = new FileHelperAsyncEngine<DepthCounterCSV>();
            using (depthEngine.BeginReadString(csv[MetricsCountersNames.depthCounter]))
            {

                // The engine is IEnumerable
                foreach (DepthCounterCSV cust in depthEngine)
                {
                    if (cust.Name == line_name || all)
                    {
                        results += $"{cust.DepthAverage},{cust.WidthAverage},{cust.WidthMax},";
                    }
                }
            }

            var widthEngine = new FileHelperAsyncEngine<WidthCounterCSV>();
            using (widthEngine.BeginReadString(csv[MetricsCountersNames.widthCounter]))
            {
                // The engine is IEnumerable
                foreach (WidthCounterCSV cust in widthEngine)
                {
                    if (cust.Name == line_name || all)
                    {
                        results += $"{cust.InputWidthAverage},{cust.ExtraWidthAverage},";
                    }
                }
            }

            results += $"{comment},";
            return results;
        }
    }
}