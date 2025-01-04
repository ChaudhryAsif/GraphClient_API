using System.IdentityModel.Tokens.Jwt;

namespace GraphClient_API.Services
{
    public class TokenDecoder
    {
        public static IDictionary<string, List<string>> DecodeAccessToken(string accessToken)
        {
            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(accessToken))
                throw new ArgumentException("Invalid access token");

            var jwtToken = handler.ReadJwtToken(accessToken);

            // Group claims by key, supporting multiple values for the same key
            var claims = jwtToken.Claims.GroupBy(c => c.Type)
                                        .ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToList());

            return claims;
        }
    }
}
