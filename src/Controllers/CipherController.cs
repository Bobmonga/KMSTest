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
        [HttpGet("CreateKey/{description}")]
        public ActionResult<CreateKeyResponse> CreateKey(string description)
        {
            using (var kms = new AmazonKeyManagementServiceClient())
            {
                CreateKeyRequest createKeyRequest = new CreateKeyRequest()
                {
                    Description = description,                    
                };

                CreateKeyResponse createKeyResponse = kms.CreateKeyAsync(createKeyRequest).Result;

                return createKeyResponse;
            }
        }

        [HttpGet("CreateAlias/{keyId}/{aliasName}")]
        public ActionResult<CreateAliasResponse> CreateAlias(string keyId, string aliasName)
        {
            using (var kms = new AmazonKeyManagementServiceClient())
            {
                CreateAliasRequest createAliasRequest = new CreateAliasRequest()
                {
                    TargetKeyId = keyId,
                    AliasName = "alias/" + aliasName
                };
 
                CreateAliasResponse createAliasResponse = kms.CreateAliasAsync(createAliasRequest).Result;

                return createAliasResponse;
            }
        }

        [HttpGet("PutKeyPolicy/{keyId}")]
        public ActionResult<PutKeyPolicyResponse> PutKeyPolicy(string keyId)
        {
            using (var kms = new AmazonKeyManagementServiceClient())
            {
                PutKeyPolicyRequest putKeyPolicyRequest = new PutKeyPolicyRequest()
                {
                    KeyId = keyId,
                    PolicyName = "default",
                    Policy = "{" +
                    "  \"Version\": \"2012-10-17\"," +
                    "  \"Statement\": [" +
                    "    {\"Sid\": \"Allow access for ecsRole\"," +
                    "    \"Effect\": \"Allow\"," +
                    "    \"Principal\": {\"AWS\": \"arn:aws:iam::313549930986:role/ecsRole\"}," +
                    "    \"Action\": [" +
                    "      \"kms:GenerateDataKey\"," +
                    "      \"kms:Decrypt\"," +
                    "      \"kms:Encrypt\"" +
                    "    ]," +
                    "    \"Resource\": \"*\"}," +
                    "    {\"Sid\": \"Allow full admin access for root\"," +
                    "    \"Effect\": \"Allow\"," +
                    "    \"Principal\": {\"AWS\": \"arn:aws:iam::313549930986:root\"}," +
                    "    \"Action\": [" +
                    "      \"kms:*\"" +
                    "    ]," +
                    "    \"Resource\": \"*\"}" +
                    "  ]" +
                    "}"
                };
 
                PutKeyPolicyResponse putKeyPolicyResponse = kms.PutKeyPolicyAsync(putKeyPolicyRequest).Result;

                return putKeyPolicyResponse;
            }
        }

        [HttpGet("CreateDataKey/{keyId}")]
        public ActionResult<KeyResponse> CreateDataKey(string keyId)
        {
            using (var kms = new AmazonKeyManagementServiceClient())
            {
                GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest()
                {
                    KeyId = keyId,
                    KeySpec = DataKeySpec.AES_256
                };

                GenerateDataKeyResponse generateDataKeyResponse = kms.GenerateDataKeyAsync(generateDataKeyRequest).Result;

                KeyResponse keyResponse = new KeyResponse();
                keyResponse.Plain = Help.StreamToString(generateDataKeyResponse.Plaintext);
                keyResponse.Cipher = Help.StreamToString(generateDataKeyResponse.CiphertextBlob);

                return keyResponse;
            }
        }

        [HttpGet("Encrypt/{dataKey}/{plain}")]
        public ActionResult<string> Encrypt(string plain)
        {
            return plain;
        }

        [HttpGet("Decrypt/{dataKey}/{cipher}")]
        public ActionResult<string> Decrypt(string dataKey, string cipher)
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
