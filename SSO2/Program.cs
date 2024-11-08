using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddict.Server.AspNetCore;
using SSO2;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure logging for debugging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication.OpenIdConnect", LogLevel.Debug);
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication.Cookies", LogLevel.Debug);

// Step 1: Configure DbContext with OpenIddict entities
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

// Step 2: Configure OpenIddict as the authorization server
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token");

        options.AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange();

        options.RegisterScopes(OpenIddictConstants.Scopes.OpenId,
                               OpenIddictConstants.Scopes.Profile,
                               OpenIddictConstants.Scopes.Email);

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

var armyAzureAdConfig = builder.Configuration.GetSection("ArmyAzureAd");

// Step 3: Configure Azure AD as an external provider
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "aad";
})
.AddCookie(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
})
.AddOpenIdConnect("aad", aadOptions =>
{
    aadOptions.ClientId = armyAzureAdConfig["ClientId"];
    aadOptions.ClientSecret = armyAzureAdConfig["ClientSecret"];
    aadOptions.Authority = armyAzureAdConfig["Authority"];
    aadOptions.ResponseType = OpenIdConnectResponseType.Code;
    aadOptions.SaveTokens = true;
    aadOptions.Scope.Add("openid");
    aadOptions.Scope.Add("profile");
    aadOptions.Scope.Add("email");
    aadOptions.SkipUnrecognizedRequests = false;
});

// Step 4: Add CORS policy
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost3000", builder =>
    {
        builder.WithOrigins("http://localhost:3000")
                .WithHeaders("Authorization", "Content-Type")
               .AllowAnyMethod()    
               .AllowCredentials();
    });
});

// Step 5: Ensure authorization services are added
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors("AllowLocalhost3000");



app.UseAuthentication();
app.UseAuthorization();

await OpenIddictSeeder.SeedAsync(app.Services);

app.MapGet("/login", async (HttpContext context) =>
{
    var clientRedirectUri = context.Request.Query["redirect_uri"].ToString();

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <html>
            <body>
                <h1>Army War College Single Sign-On Server</h1>
                <button onclick=""location.href='/login/army?redirect_uri={clientRedirectUri}'"">Log on Army</button>
                <button onclick=""location.href='/login/edu?redirect_uri={clientRedirectUri}'"">Log on EDU</button>
            </body>
        </html>
    ");
});

// Army Login Endpoint
app.MapGet("/login/army", async (HttpContext context) =>
{
    var clientRedirectUri = context.Request.Query["redirect_uri"].ToString();

    await context.ChallengeAsync("aad", new AuthenticationProperties
    {
        RedirectUri = "https://localhost:7274/connect/callback",
        Items = { { "redirect_uri", clientRedirectUri } }
    });
});

// EDU Login Endpoint (currently inactive)
app.MapGet("/login/edu", async (HttpContext context) =>
{
    var clientRedirectUri = context.Request.Query["redirect_uri"].ToString();

    // Placeholder for EDU-specific logic
    await context.Response.WriteAsync($"EDU login is currently inactive. Intended redirect: {clientRedirectUri}");
});

// Callback Endpoint to Handle Azure AD's Response and Issue Token
app.MapGet("/connect/callback", async (HttpContext context) =>
{
    var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    if (result.Succeeded)
    {
        var email = result.Principal.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");

        if (email == null)
        {
            await context.Response.WriteAsync("Email claim not found.");
            return;
        }

        // Define claims for the JWT token
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, email),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // JWT settings
        var issuer = "https://localhost:7274";
        var audience = "resource-server-1";
        var secretKey = "YourSuperSecureRandomSecretKey123!";
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddMinutes(30);

        // Create the JWT token
        var token = new JwtSecurityToken(
            issuer,
            audience,
            claims,
            expires: expires,
            signingCredentials: creds
        );

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenString = tokenHandler.WriteToken(token);

        // Retrieve the client-specified redirect URI from the login endpoint
        var clientRedirectUri = result.Properties?.Items["redirect_uri"];

        // Redirect to the client with the token in the query string
        var redirectUri = $"{clientRedirectUri}?token={tokenString}";
        context.Response.Redirect(redirectUri);
    }
    else
    {
        await context.Response.WriteAsync("Authentication failed.");
    }
});

app.Run();


