using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

public class TokenValidator
{
    public static string TanetId { get; private set; }
    public static string Audience { get; private set; }

    public static void Initialize(IConfiguration configuration)
    {
        TanetId = configuration["AzureAd:TenantId"];
        Audience = configuration["AzureAd:Audience"];
    }

    public static async Task<bool> ValidateTokenAsync(string token)
    {
        try
        {
            // Create a symmetric security key for validating the token's signature.
            SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("secret".PadRight((512 / 8), '\0')));

            // Define the valid issuer (Azure AD tenant ID) for the token.
            string issuer = $"https://sts.windows.net/{TanetId}/"; // Azure AD Issuer

            // Fetch the OpenID Connect configuration from Azure AD.
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>($"https://sts.windows.net/{TanetId}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());

            // Retrieve the OpenID Connect configuration, including signing keys.
            var config = await configurationManager.GetConfigurationAsync();

            // Set up token validation parameters.
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,

                ValidateAudience = true,
                ValidAudience = Audience,

                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5),

                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,

                // Custom signature validation logic (not typically required when using issuer signing keys).
                SignatureValidator = delegate (string token, TokenValidationParameters parameters)
                {
                    var jwt = new JwtSecurityToken(token);
                    jwt.SigningKey = signingKey;
                    return jwt;
                },
            };

            // Create a token handler for validating the JWT.
            var handler = new JwtSecurityTokenHandler();

            // Validate the token using the specified validation parameters.
            var claimsPrincipal = handler.ValidateToken(token, tokenValidationParameters, out var validatedToken);

            // If no exception is thrown, the token is valid.
            Console.WriteLine("Token is valid.");

            if (validatedToken != null) { 
            }
            return claimsPrincipal is null ? false : claimsPrincipal.Identity.IsAuthenticated;
        }
        catch (Exception ex)
        {
            // Handle validation errors (e.g., invalid signature, expired token).
            Console.WriteLine($"Token validation failed: {ex.Message}");
        }

        return false;
    }
}