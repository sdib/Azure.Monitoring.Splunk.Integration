﻿//
// AzureFunctionForSplunkVS
//
// Copyright (c) Microsoft Corporation
//
// All rights reserved. 
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy 
// of this software and associated documentation files (the ""Software""), to deal 
// in the Software without restriction, including without limitation the rights 
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
// copies of the Software, and to permit persons to whom the Software is furnished 
// to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all 
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
using Microsoft.Azure.WebJobs.Host;
using Newtonsoft.Json;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Amadeus.Azure.Monitoring.Splunk.Logs
{
    public abstract class AzMonMessages
    {
        public ILogger Log { get; set; }

        public virtual List<string> DecomposeIncomingBatch(string[] messages)
        {
            List<string> decomposed = new List<string>();

            foreach (var message in messages)
            {
                dynamic obj = JsonConvert.DeserializeObject<Dictionary<string, dynamic>>(message);

                if (((IDictionary<string, dynamic>)obj).ContainsKey("records"))
                {
                    var records = obj["records"];

                    foreach (var record in records)
                    {
                        string stringRecord = record.ToString();

                        decomposed.Add(stringRecord);
                    }
                } else
                {
                    Log.LogError("AzMonMessages: invalid message structure, missing 'records'");
                }
            }

            return decomposed;
        }

        public AzMonMessages(ILogger log)
        {
            Log = log;
        }

    }

    public class ActivityLogMessages : AzMonMessages
    {
        public ActivityLogMessages(ILogger log) : base(log) { }
    }

    public class DiagnosticLogMessages : AzMonMessages
    {
        public DiagnosticLogMessages(ILogger log) : base(log) { }
    }

    public class MetricMessages : AzMonMessages
    {
        public MetricMessages(ILogger log) : base(log) { }
    }

    public class WadMessages : AzMonMessages
    {
        public WadMessages(ILogger log): base(log) { }
    }

    public class LadMessages : AzMonMessages
    {
        public LadMessages(ILogger log) : base(log) { }

        public override List<string> DecomposeIncomingBatch(string[] messages)
        {
            List<string> decomposed = new List<string>();

            foreach (var record in messages)
            {
                string stringRecord = record.ToString();

                decomposed.Add(stringRecord);
            }

            return decomposed;
        }
    }
}
