using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Microsoft.IdentityModel.Tokens;

[assembly:LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace LambdaAuthorizer;

public class Authorizer
{
    public async Task<APIGatewayCustomAuthorizerResponse> Auth(APIGatewayCustomAuthorizerRequest request)
    {
        
        
        var idToken = request.QueryStringParameters["token"];
        Console.WriteLine($"Token is {idToken}");
        var idTokenDetails = new JwtSecurityToken(idToken);

        var kid = idTokenDetails.Header["kid"].ToString();
        var issuer = idTokenDetails.Claims.First(x => x.Type == "iss").Value;
        var audience = idTokenDetails.Claims.First(x => x.Type == "aud").Value;
        var userId = idTokenDetails.Claims.First(x => x.Type == "sub").Value;
        
        var response = new APIGatewayCustomAuthorizerResponse()
        {
            PrincipalID = userId,
            PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
            {
                Version = "2012-10-17",
                Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>()
                {
                    new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                    {
                        Action = new HashSet<string>(){"execute-api:Invoke"},
                        Effect = "Allow",
                        Resource = new HashSet<string>(){request.MethodArn}
                    }
                }
            }
        };
        

        var secretsClient = new AmazonSecretsManagerClient();
        var secret = await secretsClient.GetSecretValueAsync(new GetSecretValueRequest
        {
            SecretId = "hotelCognitoKey"
        });

        var privateKeys = secret.SecretString;

        Console.WriteLine($"JWKS set: {privateKeys}");
        var jwks = new JsonWebKeySet(privateKeys);
        
        foreach (var key in jwks.Keys)
        {
            Console.WriteLine(key.Kid);
        }
        var privateKey = jwks.Keys.First(x => x.Kid == kid);

        var handler = new JwtSecurityTokenHandler();
        var result = await handler.ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = privateKey
        });

        if (!result.IsValid) throw new UnauthorizedAccessException("Token not valid");

        var apiGroupMapping = new Dictionary<string, string>()
        {
            {"listadminshotel+", "Admin"},
            {"admin+", "Admin"}
        };

        var expectdGroup = apiGroupMapping.FirstOrDefault(x =>
            request.Path.Contains(x.Key, StringComparison.InvariantCultureIgnoreCase));

        if (!expectdGroup.Equals(default(KeyValuePair<string, string>)))
        {
            var userGroup = idTokenDetails.Claims.First(x => x.Type == "cognito:groups").Value;
            if (string.Compare(userGroup , expectdGroup.Value, 
                    StringComparison.InvariantCultureIgnoreCase) != 0)
            {
                response.PolicyDocument.Statement[0].Effect = "Deny";
            }
        }
        
        return response;
    }
}