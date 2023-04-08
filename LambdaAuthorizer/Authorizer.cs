using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Microsoft.IdentityModel.Tokens;

namespace LambdaAuthorizer;

public class Authorizer
{
    public async Task<APIGatewayCustomAuthorizerResponse> Auth(APIGatewayCustomAuthorizerRequest request)
    {
        var respone = new APIGatewayCustomAuthorizerResponse();

        var idToken = request.AuthorizationToken;
        var idTokenDetails = new JwtSecurityToken(idToken);

        var kid = idTokenDetails.Header["kid"].ToString();
        var issuer = idTokenDetails.Claims.First(x => x.Type == "iss").Value;
        var audience = idTokenDetails.Claims.First(x => x.Type == "aud").Value;

        var secretsClient = new AmazonSecretsManagerClient();
        var secret = await secretsClient.GetSecretValueAsync(new GetSecretValueRequest
        {
            SecretId = "hotelCognitoKey"
        });

        var privateKeys = secret.SecretString;

        var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(privateKeys, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        var privateKey = jwks.Keys.First(x => x.Kid == kid);

        var handler = new JwtSecurityTokenHandler();
        var result = await handler.ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = privateKey
        });

        if (!result.IsValid) throw new UnauthorizedAccessException("Token not valid");


        return respone;
    }
}