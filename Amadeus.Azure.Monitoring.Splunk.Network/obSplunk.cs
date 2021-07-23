using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Amadeus.Azure.Monitoring.Splunk.Network
{
    public partial class Util
    {
        public static async Task<int> obSplunk(string newClientContent, ILogger log)
        {
            //
            // newClientContent looks like this:
            //
            // {
            //   "records":[
            //     {...},
            //     {...}
            //     ...
            //   ]
            // }
            //

            string splunkAddress = Util.GetEnvironmentVariable("splunkAddress");
            string splunkToken = Util.GetEnvironmentVariable("nsgSplunkToken");

            if (splunkAddress.Length == 0 || splunkToken.Length == 0)
            {
                log.LogError("Values for splunkAddress and splunkToken are required.");
                return 0;
            }

            int bytesSent = 0;

            foreach (var transmission in convertToSplunkList(newClientContent, log))
            {
                var client = new SingleHttpClientInstance();
                try
                {
                    HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, splunkAddress);
                    req.Headers.Accept.Clear();
                    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    req.Headers.Add("Authorization", "Splunk " + splunkToken);
                    req.Content = new StringContent(transmission, Encoding.UTF8, "application/json");
                    HttpResponseMessage response = await SingleHttpClientInstance.SendToSplunk(req);
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        throw new System.Net.Http.HttpRequestException($"StatusCode from Splunk: {response.StatusCode}, and reason: {response.ReasonPhrase}");
                    }
                }
                catch (System.Net.Http.HttpRequestException e)
                {
                    throw new System.Net.Http.HttpRequestException("Sending to Splunk. Is Splunk service running?", e);
                }
                catch (Exception f)
                {
                    throw new System.Exception("Sending to Splunk. Unplanned exception.", f);
                }
                bytesSent += transmission.Length;
            }
            return bytesSent;
        }

        static System.Collections.Generic.IEnumerable<string> convertToSplunkList(string newClientContent, ILogger log)
        {
            foreach (var messageList in denormalizedSplunkEvents(newClientContent, null, log))
            {

                StringBuilder outgoingJson = StringBuilderPool.Allocate();
                outgoingJson.Capacity = MAXTRANSMISSIONSIZE;

                try
                {
                    foreach (var message in messageList)
                    {
                        var messageAsString = JsonConvert.SerializeObject(message, new JsonSerializerSettings
                        {
                            NullValueHandling = NullValueHandling.Ignore
                        });
                        outgoingJson.Append(messageAsString);
                    }
                    yield return outgoingJson.ToString();
                }
                finally
                {
                    StringBuilderPool.Free(outgoingJson);
                }

            }
        }

        public static bool ValidateMyCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErr)
        {
            var splunkCertThumbprint = GetEnvironmentVariable("splunkCertThumbprint");

            // if user has configured a cert, must match
            var numcerts = chain.ChainElements.Count;
            var cacert = chain.ChainElements[numcerts - 1].Certificate;

            var thumbprint = cacert.GetCertHashString().ToLower();
            if (thumbprint == splunkCertThumbprint)
                return true;

            return false;
        }
	}
}
