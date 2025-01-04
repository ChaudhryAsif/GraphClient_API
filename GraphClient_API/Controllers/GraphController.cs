using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
using System.Text.Json;

namespace GraphClient_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class GraphController : ControllerBase
    {
        //private readonly GraphServiceClient _graphServiceClient;

        //public GraphController(GraphServiceClient graphServiceClient)
        //{
        //    _graphServiceClient = graphServiceClient;
        //}

        //[HttpGet("me")]
        //public async Task<IActionResult> GetMe()
        //{
        //    try
        //    {
        //        var user = await _graphServiceClient.Me.GetAsync();
        //        return Ok(user);
        //    }
        //    catch (ServiceException ex)
        //    {
        //        return StatusCode((int)ex.ResponseStatusCode, ex.Message);
        //    }
        //}

        //[HttpGet("users")]
        //public async Task<IActionResult> GetUsers()
        //{
        //    try
        //    {
        //        var users = await _graphServiceClient.Users.GetAsync();
        //        return Ok(users);
        //    }
        //    catch (ServiceException ex)
        //    {
        //        return StatusCode((int)ex.ResponseStatusCode, ex.Message);
        //    }
        //}

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;

        public GraphController(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }

        [HttpGet("call-api2")]
        public async Task<IActionResult> CallApi2()
        {
            await getTokenAsync();
            var clientId = _configuration["AzureAd:ClientId"];
            var clientSecret = _configuration["AzureAd:ClientSecret"];
            var tenantId = _configuration["AzureAd:TenantId"];
            var api2Scope = "api://3dca47c7-1f07-48f1-ac40-61ed8641bb64/.default"; // _configuration["AzureAd:Api2Scope"];
            //var api2Scope = _configuration["AzureAd:Api2Scope"];

            var clientCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            var tokenRequestContext = new TokenRequestContext(new[] { api2Scope });
            var token = await clientCredential.GetTokenAsync(tokenRequestContext);


            var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);

            var response = await httpClient.GetAsync("https://localhost:7166/api/Home");
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<object>(content);

            return Ok(result);
        }

        private async Task getTokenAsync()
        {

            // Initialize MSAL Client Application
            var app = ConfidentialClientApplicationBuilder.Create("3dca47c7-1f07-48f1-ac40-61ed8641bb64")
                .WithClientSecret("dZu8Q~mKAxr25XU91481ys71qFksDVIPldCwzbin")
                .WithAuthority(new Uri("https://login.microsoftonline.com/f5661410-af98-40aa-8597-07348fece1b5"))
                .Build();

            string[] scopes = new[] { "api://3dca47c7-1f07-48f1-ac40-61ed8641bb64/.default" };
              
            // Acquire Token for Client
            AuthenticationResult result = await app.AcquireTokenForClient(scopes).ExecuteAsync();

            var authResult = await app.AcquireTokenForClient(new[] { "https://graph.microsoft.com/.default" }).ExecuteAsync();

            // Use the Access Token
            string accessToken = result.AccessToken;

            var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authResult.AccessToken);

            var response = await httpClient.GetAsync("https://localhost:7166/api/Home/Get");
            response.EnsureSuccessStatusCode();

        }
    }
}
