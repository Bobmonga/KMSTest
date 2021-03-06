﻿using System;
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
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Amazon.Auth.AccessControlPolicy;

namespace KMSTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CipherController : ControllerBase
    {
        IAmazonKeyManagementService _kmsClient;
        IAmazonSecurityTokenService _stsClient;

        public CipherController(IAmazonKeyManagementService kmsClient, IAmazonSecurityTokenService stsClient)
        {
            _kmsClient = kmsClient;
            _stsClient = stsClient;
        }

        [HttpGet("CreateKey/{description}")]
        public ActionResult<CreateKeyResponse> CreateKey(string description)
        {
            CreateKeyRequest createKeyRequest = new CreateKeyRequest()
            {
                Description = description,                    
            };

            CreateKeyResponse createKeyResponse = _kmsClient.CreateKeyAsync(createKeyRequest).Result;

            return createKeyResponse;
        }

        [HttpGet("CreateAlias/{keyId}/{aliasName}")]
        public ActionResult<CreateAliasResponse> CreateAlias(string keyId, string aliasName)
        {
            CreateAliasRequest createAliasRequest = new CreateAliasRequest()
            {
                TargetKeyId = keyId,
                AliasName = "alias/" + aliasName
            };
 
            CreateAliasResponse createAliasResponse = _kmsClient.CreateAliasAsync(createAliasRequest).Result;

            return createAliasResponse;
        }

        [HttpGet("PutKeyPolicy/{keyId}")]
        public ActionResult<PutKeyPolicyResponse> PutKeyPolicy(string keyId)
        {
            Policy policy;

            GetCallerIdentityResponse getCallerIdentityResponse = _stsClient.GetCallerIdentityAsync(new GetCallerIdentityRequest()).Result;

            policy = Help.GetPolicy(
                _kmsClient.Config.RegionEndpoint.SystemName,
                getCallerIdentityResponse.Account,
                getCallerIdentityResponse.Arn,
                keyId);

            PutKeyPolicyRequest putKeyPolicyRequest = new PutKeyPolicyRequest()
            {
                KeyId = keyId,
                PolicyName = "default",
                Policy = policy.ToJson()
            };
 
            PutKeyPolicyResponse putKeyPolicyResponse = _kmsClient.PutKeyPolicyAsync(putKeyPolicyRequest).Result;

            return putKeyPolicyResponse;
        }

        [HttpGet("CreateDataKey/{keyId}")]
        public ActionResult<KeyResponse> CreateDataKey(string keyId)
        {
            GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest()
            {
                KeyId = keyId,
                KeySpec = DataKeySpec.AES_256
            };

            GenerateDataKeyResponse generateDataKeyResponse = _kmsClient.GenerateDataKeyAsync(generateDataKeyRequest).Result;

            KeyResponse keyResponse = new KeyResponse();
            keyResponse.Plain = Help.StreamToString(generateDataKeyResponse.Plaintext);
            keyResponse.Cipher = Help.StreamToString(generateDataKeyResponse.CiphertextBlob);

            return keyResponse;
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

    public static Policy GetPolicy(string region, string accountId, string role, string keyId)
    {
        Statement statementKeyUser = new Statement(Statement.StatementEffect.Allow);
        statementKeyUser.Id = "Allow access for EC2 role";
        statementKeyUser.Principals = new List<Principal>()
        {
            new Principal($"arn:aws:iam::{accountId}:role/ListUserRole")
        };
        statementKeyUser.Actions = new List<ActionIdentifier>()
        {
            new ActionIdentifier("kms:GenerateDataKey"),
            new ActionIdentifier("kms:Decrypt"),
            new ActionIdentifier("kms:Encrypt")
        };
        statementKeyUser.Resources = new List<Resource>
        {
            new Resource($"arn:aws:kms:{region}:{accountId}:key/{keyId}")
        };

        Statement statementAdmin = new Statement(Statement.StatementEffect.Allow);
        statementAdmin.Id = "Allow full admin access for root";
        statementAdmin.Principals = new List<Principal>()
        {
            new Principal($"arn:aws:iam::{accountId}:root")
        };
        statementAdmin.Actions = new List<ActionIdentifier>()
        {
            new ActionIdentifier("kms:*"),
        };
        statementAdmin.Resources = new List<Resource>
        {
            new Resource($"arn:aws:kms:{region}:{accountId}:key/{keyId}")
        };

        //TODO - Add a condition?
        //statement.Conditions.Add(ConditionFactory..NewIpAddressCondition(ipAddress));

        var policy = new Policy();
        policy.Statements.Add(statementKeyUser);
        policy.Statements.Add(statementAdmin);

        return policy;
    }
}
