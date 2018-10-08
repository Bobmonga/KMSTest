using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Amazon;
using Amazon.Runtime;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using System.IO;
using KMSTest.Models;

namespace KMSTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CipherController : ControllerBase
    {
        BasicAWSCredentials _credentials;
        AmazonKeyManagementServiceConfig _kmsConfig;

        public CipherController()
        {
            _credentials = new BasicAWSCredentials("AKIAIBBB5AMKSV6RSIPQ", "OZLBck0u3tom3r9BHHuLMXlX6NJILNLem/zb9ip7");
            _kmsConfig = new AmazonKeyManagementServiceConfig();
            _kmsConfig.RegionEndpoint = RegionEndpoint.EUWest1;
        }

        // GET api/values/5
        [HttpGet("Encrypt/{plain}")]
        public ActionResult<KeyResponse> Encrypt(string plain)
        {
            using (var kms = new AmazonKeyManagementServiceClient(_credentials, _kmsConfig))
            {
                GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest()
                {
                    KeyId = "alias/TestCMK",
                    KeySpec = DataKeySpec.AES_256
                };

                GenerateDataKeyResponse generateDataKeyResponse = kms.GenerateDataKeyAsync(generateDataKeyRequest).Result;

                KeyResponse keyResponse = new KeyResponse();
                keyResponse.Plain = Help.StreamToString(generateDataKeyResponse.Plaintext);
                keyResponse.Cipher = Help.StreamToString(generateDataKeyResponse.CiphertextBlob);

                return keyResponse;
            }
        }

        // GET api/values/5
        [HttpGet("CreateKey")]
        public ActionResult<CreateKeyResponse> CreateKey(string keyId)
        {
            using (var kms = new AmazonKeyManagementServiceClient(_credentials, _kmsConfig))
            {
                CreateKeyRequest createKeyRequest = new CreateKeyRequest()
                {
                    Description = "TestCMK"
                };

                CreateKeyResponse createKeyResponse = kms.CreateKeyAsync(createKeyRequest).Result;

                return createKeyResponse;
            }
        }

        [HttpGet("Decrypt/{cipher}")]
        public ActionResult<string> Decrypt(string cipher)
        {
            return cipher;
        }
    }

    static class Help
    {
        /// <summary>
        /// Converts a memory stream to string
        /// </summary>
        /// <param name="memStream">The memory stream to convert</param>
        /// <returns></returns>
        public static string StreamToString(MemoryStream memStream)
        {
            byte[] bytes = new byte[memStream.Length];
            memStream.Read(bytes, 0, bytes.Length);
            return Convert.ToBase64String(bytes);
       }
    }
}
