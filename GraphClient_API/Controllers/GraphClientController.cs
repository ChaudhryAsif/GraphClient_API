using Azure.Core;
using Azure.Identity;
using GraphClient_API.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Identity.Client;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;

namespace GraphClient_API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class GraphClientController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public GraphClientController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        [Route("GetAllUser")]
        public async Task<IActionResult> GetAllUserAsync()
        {
            var users = new List<User>();
            try
            {
                // get graph client
                var graphClient = GraphClient();

                // Example: Get users
                var userList = await graphClient.Users.GetAsync();

                users = userList.Value;
            }
            catch (Exception)
            {
                throw;
            }


            return Ok(users);
        }

        [HttpGet]
        [Route("ById")]
        public async Task<IActionResult> GetUserByIdAsync(string userId)
        {
            var user = new User();
            try
            {
                // get graph client
                var graphClient = GraphClient();

                user = await graphClient.Users[userId].GetAsync();
            }
            catch (ServiceException ex)
            {
                Console.WriteLine($"Error retrieving user: {ex.Message}");
            }

            return Ok(user);
        }

        [HttpPost]
        [Route("Create")]
        public async Task<IActionResult> AddADUserAsync()
        {
            // get graph client
            var graphClient = GraphClient();

            var user = new User
            {
                AccountEnabled = true,
                DisplayName = "John Doe12",
                MailNickname = "johndoe12",  // Ensure it's unique
                UserPrincipalName = "johndoe12@ma232505gmail.onmicrosoft.com",  // Use a verified domain
                PasswordProfile = new PasswordProfile
                {
                    Password = "testpasswordValue@122",
                    ForceChangePasswordNextSignIn = false,
                }
            };

            // Post the request to create the user
            var result = await graphClient.Users.PostAsync(user);

            return Ok(user);
        }

        [HttpGet]
        [Route("Delete/{userid}")]
        public async Task<IActionResult> DeleteUserByIdAsync(string userid)
        {
            var user = new User();
            try
            {
                // get graph client
                var graphClient = GraphClient();

                await graphClient.Users[userid].DeleteAsync();
            }
            catch (ServiceException ex)
            {
                Console.WriteLine($"Error retrieving user: {ex.Message}");
            }

            return Ok();
        }

        [HttpPost]
        [Route("LoggedIn")]
        public async Task<IActionResult> LoggedInAsync()
        {
            try
            {
                var tenantId = _configuration["tenantId"];
                var clientId = _configuration["clientId"];

                var scopes = new[] { "User.Read", "Mail.Read" };

                // Configure InteractiveBrowserCredential with token cache options
                var credential = new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
                {
                    ClientId = clientId,
                    TenantId = tenantId
                });

                // Initialize GraphServiceClient
                var graphClient = new GraphServiceClient(credential, scopes);


                // Attempt to get the logged-in user's profile
                var user = await graphClient.Me.GetAsync();

                Console.WriteLine($"logged-in user, {user?.DisplayName}");

                // Retrieve the access token explicitly (ensure it is refreshed)
                var tokenRequestContext = new TokenRequestContext(scopes);
                var accessToken = await credential.GetTokenAsync(tokenRequestContext);

                //await Redirect_To_APIAsync(accessToken.Token);

                Console.WriteLine($"Access Token: {accessToken.Token}");

                bool isExpired = IsTokenExpired(accessToken.Token);

                if (!isExpired)
                {
                    // validate token
                    var isValid = await TokenValidator.ValidateTokenAsync(accessToken.Token);

                    return Ok(new {IsTokenValid = isValid, Token = accessToken.Token });
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            return Ok();
        }

        // Usage
        private GraphServiceClient GetGraphClient(string accessToken)
        {
            var authenticationProvider = new CustomAuthenticationProvider(accessToken);
            return new GraphServiceClient(authenticationProvider);
        }

        private async Task<string> GetAuthTokenAsync()
        {
            var tenantId = _configuration["tenantId"];
            var clientId = _configuration["clientId"];
            var clientSecret = _configuration["clientSecret"];
            string scope = "https://graph.microsoft.com/.default";

            // Configure authentication
            var confidentialClient = ConfidentialClientApplicationBuilder.Create(clientId)
                                                                         .WithClientSecret(clientSecret)
                                                                         .WithAuthority(new Uri($"https://login.microsoftonline.com/{tenantId}"))
                                                                         .Build();
            var clientSecretCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);

            // Get token
            var authResult = await confidentialClient.AcquireTokenForClient(new[] { "https://graph.microsoft.com/.default" }).ExecuteAsync();

            var token = authResult.AccessToken;

            return token;
        }

        private GraphServiceClient GraphClient()
        {
            var tenantId = _configuration["tenantId"];
            var clientId = _configuration["clientId"];
            var clientSecret = _configuration["clientSecret"];

            // Create a credential
            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);

            // Create a GraphServiceClient
            var graphClient = new GraphServiceClient(credential);

            return graphClient;
        }

        private bool IsTokenExpired(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                var expirationDate = jwtToken.ValidTo;
                return expirationDate < DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decoding token: {ex.Message}");
                return true; // Assuming expired if decoding fails
            }
        }

        private async Task<User?> GetUserByIdAsync(string accessToken, string userIdOrPrincipalName)
        {
            var graphClient = GetGraphClient(accessToken);

            try
            {
                // Replace {userIdOrPrincipalName} with the actual ID or userPrincipalName
                var user = await graphClient.Users[userIdOrPrincipalName].GetAsync();
                return user;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return null;
            }
        }

        private void GetUserInfoFromToken(string accessToken)
        {
            var claims = TokenDecoder.DecodeAccessToken(accessToken);

            // Extract relevant user details
            var userId = claims.ContainsKey("oid") ? claims["oid"].FirstOrDefault() : "N/A"; // Object ID
            var email = claims.ContainsKey("email") ? claims["email"].FirstOrDefault() : "N/A";
            var displayName = claims.ContainsKey("name") ? claims["name"].FirstOrDefault() : "N/A";
            var roles = claims.ContainsKey("roles") ? string.Join(", ", claims["roles"]) : "None";

            Console.WriteLine($"User ID: {userId}");
            Console.WriteLine($"Email: {email}");
            Console.WriteLine($"Name: {displayName}");
            Console.WriteLine($"Roles: {roles}");
        }

        private async Task GetUserInfoAsync(string accessToken = "")
        {
            var tenantId = _configuration["tenantId"];
            var clientId = _configuration["clientId"];
            var clientSecret = _configuration["clientSecret"];

            var redirectUri = new Uri("http://localhost:5049/GraphClient/GetAllUser"); // Make sure it matches the Azure App registration

            try
            {
                // Use InteractiveBrowserCredential for user authentication
                var credential = new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
                {
                    ClientId = clientId,
                    TenantId = tenantId,
                    RedirectUri = redirectUri
                });

                // Create GraphServiceClient with delegated credentials
                var graphClient = new GraphServiceClient(credential);

                // Fetch user profile for the signed-in user
                var user = await graphClient.Me.GetAsync();
                Console.WriteLine($"User Display Name: {user.DisplayName}");
                Console.WriteLine($"User Email: {user.Mail}");
            }
            catch (MsalServiceException msalEx)
            {
                // Log more details from the exception
                Console.WriteLine($"Authentication failed: {msalEx.Message}");
                Console.WriteLine($"Correlation ID: {msalEx.CorrelationId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

        }

        private async Task GetUserInfoTestAsync(string accessToken)
        {
            var tenantId = _configuration["tenantId"];
            var clientId = _configuration["clientId"];
            var clientSecret = _configuration["clientSecret"];

            try
            {
                // Scopes required for Microsoft Graph
                var scopes = new[] { "User.Read" };

                var redirectUri = new Uri("http://localhost:7207"); // Redirect URI registered in Azure AD

                // Use InteractiveBrowserCredential for authentication
                var credential = new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
                {
                    ClientId = clientId,
                    TenantId = tenantId,
                    RedirectUri = redirectUri
                });

                // Initialize Microsoft Graph Client with InteractiveBrowserCredential
                var graphClient = new GraphServiceClient(credential, scopes);

                // Fetch the signed-in user's profile
                var user = await graphClient.Me.GetAsync();

                // Output the user's display name
                Console.WriteLine($"Signed in as: {user?.DisplayName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        private async Task GetUsersAsync()
        {
            var tenantId = _configuration["tenantId"];
            var clientId = _configuration["clientId"];
            var clientSecret = _configuration["clientSecret"];

            // Authenticate using ClientSecretCredential
            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);

            // Create a GraphServiceClient
            var graphClient = new GraphServiceClient(credential);

            try
            {
                // Fetch a specific user or other resources
                var users = await graphClient.Users.GetAsync();
                foreach (var user in users.Value)
                {
                    Console.WriteLine($"User: {user.DisplayName} ({user.Mail})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private async Task Redirect_To_APIAsync(string accessToken)
        {
            var tenantId = _configuration["tenantId"];
            var clientId = _configuration["clientId"];
            var clientSecret = _configuration["clientSecret"];
            var scope = $"api://{clientId}/.default";

            var confidentialClient = ConfidentialClientApplicationBuilder
                                                                        .Create(clientId)
                                                                        .WithClientSecret(clientSecret)
                                                                        .WithAuthority($"https://login.microsoftonline.com/{tenantId}")
                                                                        .Build();

            var authResult = await confidentialClient.AcquireTokenForClient(new[] { $"api://{clientId}/.default" }).ExecuteAsync();
            //string accessToken = authResult.AccessToken;

            Console.WriteLine("Access Token: " + accessToken);

            // Use the token to call the API
            string apiUrl = "https://localhost:7166/api/Home/Get";
            var response = await CallApiAsync(apiUrl, authResult.AccessToken);
            Console.WriteLine(await response.Content.ReadAsStringAsync());
        }

        private async Task<HttpResponseMessage> CallApiAsync(string url, string token)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return await client.GetAsync(url);
            }
        }
    }
}
