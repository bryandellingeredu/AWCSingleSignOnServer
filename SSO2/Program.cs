
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Abstractions;
using System.Text.Json;

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

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options.AllowAuthorizationCodeFlow();

        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token");

        options.RegisterScopes(OpenIddictConstants.Scopes.OpenId, "api");

        options.AddEphemeralSigningKey();
        options.AddEphemeralEncryptionKey();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough();
    })
    .AddClient(options =>
    {
        // Add an ephemeral encryption key
        options.AddEphemeralEncryptionKey();
        options.AddEphemeralSigningKey();

        options.UseWebProviders()
            .AddMicrosoft(armyOptions =>
            {
                armyOptions.SetClientId(builder.Configuration["ArmyAzureAd:ClientId"] ?? throw new InvalidOperationException("ArmyAzureAd:ClientId is not configured."))
                           .SetClientSecret(builder.Configuration["ArmyAzureAd:ClientSecret"] ?? throw new InvalidOperationException("ArmyAzureAd:ClientSecret is not configured."))
                           .SetTenant(builder.Configuration["ArmyAzureAd:TenantId"] ?? throw new InvalidOperationException("ArmyAzureAd:TenantId is not configured."))
                           .SetRedirectUri("/callback/login/army")
                           .SetProviderName("Army"); // Set the provider name here
            })
            .AddMicrosoft(eduOptions =>
            {
                eduOptions.SetClientId(builder.Configuration["EDUAzureAd:ClientId"] ?? throw new InvalidOperationException("EDUAzureAd:ClientId is not configured."))
                          .SetClientSecret(builder.Configuration["EDUAzureAd:ClientSecret"] ?? throw new InvalidOperationException("EDUAzureAd:ClientSecret is not configured."))
                          .SetTenant(builder.Configuration["EDUAzureAd:TenantId"] ?? throw new InvalidOperationException("EDUAzureAd:TenantId is not configured."))
                          .SetRedirectUri("/callback/login/edu")
                          .SetProviderName("EDU"); // Set the provider name here
            });

        options.AllowAuthorizationCodeFlow();

        options.UseAspNetCore()
               .EnableRedirectionEndpointPassthrough()
               .EnablePostLogoutRedirectionEndpointPassthrough();
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAnyOrigin", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});

// Step 5: Ensure authorization services are added
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors("AllowAnyOrigin");
app.UseAuthentication();
app.UseAuthorization();

// Login Page with Army and EDU buttons
app.MapGet("/login", async (HttpContext context) =>
{
    var clientRedirectUri = context.Request.Query["redirect_uri"].ToString();
    var buttonsQuery = context.Request.Query["buttons"].ToString();

    var buttonsToDisplay = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    if (!string.IsNullOrEmpty(buttonsQuery))
    {
        var buttonsArray = buttonsQuery.Split(',', StringSplitOptions.RemoveEmptyEntries);
        foreach (var button in buttonsArray)
        {
            buttonsToDisplay.Add(button.Trim().ToLower()); // Normalize to lowercase
        }
    }
    else
    {
        // Default to army and edu if buttonsQuery is empty or missing
        buttonsToDisplay.Add("army");
        buttonsToDisplay.Add("edu");
    }

    var buttonsHtml = new StringBuilder();

    if (buttonsToDisplay.Contains("army"))
    {
        buttonsHtml.Append($@"<button class=""btn"" onclick=""location.href='/login/army?redirect_uri={clientRedirectUri}'"">Log on Army</button>");
    }
    if (buttonsToDisplay.Contains("edu"))
    {
        buttonsHtml.Append($@"<button class=""btn"" onclick=""location.href='/login/edu?redirect_uri={clientRedirectUri}'"">Log on EDU</button>");
    }
    if (buttonsToDisplay.Contains("email"))
    {
        buttonsHtml.Append($@"<button class=""btn"" onclick=""location.href='/login/email?redirect_uri={clientRedirectUri}'"">Send Email Link</button>");
    }

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
    <!DOCTYPE html>
    <html lang=""en"">
    <head>
        <meta charset=""UTF-8"">
        <title>ARMY WAR COLLEGE SINGLE SIGN ON SERVER</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f0f2f5;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
            }}
            h1 {{
                color: #333;
            }}
            .button-container {{
                margin-top: 20px;
            }}
            .btn {{
                display: inline-block;
                padding: 12px 24px;
                margin: 10px;
                font-size: 16px;
                text-decoration: none;
                color: #fff;
                background-color: #007bff;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }}
            .btn:hover {{
                background-color: #0056b3;
            }}
        </style>
    </head>
    <body>
        <h1>Army War College Single Sign-On Server</h1>
        <div class=""button-container"">
            {buttonsHtml}
        </div>
    </body>
    </html>
");
});

app.MapGet("/login/email", async (HttpContext context) =>
{
    var clientRedirectUri = context.Request.Query["redirect_uri"].ToString();

    context.Response.ContentType = "text/html";
    await context.Response.WriteAsync($@"
        <!DOCTYPE html>
        <html lang=""en"">
        <head>
            <meta charset=""UTF-8"">
            <title>Email Login</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f0f2f5;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                }}
                h1 {{
                    color: #333;
                }}
                .form-container {{
                    margin-top: 20px;
                }}
                .input-field {{
                    padding: 10px;
                    font-size: 16px;
                    margin-bottom: 10px;
                }}
                .btn {{
                    padding: 10px 20px;
                    font-size: 16px;
                    background-color: #007bff;
                    color: #fff;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                }}
                .btn:hover {{
                    background-color: #0056b3;
                }}
            </style>
        </head>
        <body>
            <h1>Email Login</h1>
            <div class=""form-container"">
                <form method=""post"" action=""/login/email?redirect_uri={clientRedirectUri}"">
                    <input type=""email"" name=""email"" placeholder=""Enter your email"" class=""input-field"" required />
                    <input type=""submit"" value=""Submit"" class=""btn"" />
                </form>
            </div>
        </body>
        </html>
    ");
});

app.MapPost("/login/email", async (HttpContext context) =>
{
    var clientRedirectUri = context.Request.Query["redirect_uri"].ToString();

    // Get the email from the form
    var form = await context.Request.ReadFormAsync();
    var email = form["email"].ToString();

    if (string.IsNullOrEmpty(email))
    {
        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync("Please provide a valid email address.");
        return;
    }

    // Generate JWT token
    var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, email),
        new Claim(JwtRegisteredClaimNames.Email, email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

    var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
    var JWTSettingsConfig = configuration.GetSection("JWTSettings");

    // JWT settings
    var issuer = $"{context.Request.Scheme}://{context.Request.Host}";
    var audience = "resource-server-1";
    var secretKey = JWTSettingsConfig["SecretKey"];
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

    // Create the email content
    var redirectUri = $"{clientRedirectUri}?token={tokenString}";

    var emailContent = $@"
        <p>Please click the link below to complete your login:</p>
        <p><a href=""{redirectUri}"">{redirectUri}</a></p>
    ";

    // Prepare the email request
    var emailRequest = new
    {
        recipients = new[] { email },
        subject = "Your Login Link",
        body = emailContent
    };

    // Serialize the email request to JSON
    var jsonContent = JsonSerializer.Serialize(emailRequest);

    using var httpClient = new HttpClient();

    // Add the X-API-KEY header
    httpClient.DefaultRequestHeaders.Add("X-API-KEY", "DthdAd-JGC3XdvHOctzG6WTf7p6-eeJtXcqN4i8w7Yc");

    // Send the email via POST request
    var response = await httpClient.PostAsync(
        "https://apps.armywarcollege.edu/registration/api/SendEmail",
        new StringContent(jsonContent, Encoding.UTF8, "application/json")
    );

    if (response.IsSuccessStatusCode)
    {
        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync("An email has been sent to your address with the login link.");
    }
    else
    {
        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync("Failed to send email. Please try again later.");
    }
});

app.MapGet("/callback/login/email", async (HttpContext context) =>
{
    var token = context.Request.Query["token"].ToString();
    var clientRedirectUri = context.Request.Query["redirect_uri"].ToString();

    if (string.IsNullOrEmpty(token))
    {
        await context.Response.WriteAsync("Invalid token.");
        return;
    }

    var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
    var JWTSettingsConfig = configuration.GetSection("JWTSettings");

    var secretKey = JWTSettingsConfig["SecretKey"];
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

    var tokenHandler = new JwtSecurityTokenHandler();

    try
    {
        var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = $"{context.Request.Scheme}://{context.Request.Host}",
            ValidateAudience = true,
            ValidAudience = "resource-server-1",
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateLifetime = true
        }, out SecurityToken validatedToken);

        // Redirect to the client with the token in the query string
        var redirectUri = $"{clientRedirectUri}?token={token}";
        context.Response.Redirect(redirectUri);
    }
    catch (Exception)
    {
        await context.Response.WriteAsync("Invalid or expired token.");
    }
});



// Army Login Endpoint
app.MapGet("/login/army", async (HttpContext context) =>
{
    var properties = new AuthenticationProperties(new Dictionary<string, string>
    {
        [OpenIddictClientAspNetCoreConstants.Properties.ProviderName] = "Army",
        ["redirect_uri"] = context.Request.Query["redirect_uri"]
    })
    {
        RedirectUri = "/callback/login/army"
    };

    await context.ChallengeAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, properties);
});

// EDU Login Endpoint
app.MapGet("/login/edu", async (HttpContext context) =>
{
    var properties = new AuthenticationProperties(new Dictionary<string, string>
    {
        [OpenIddictClientAspNetCoreConstants.Properties.ProviderName] = "EDU",
        ["redirect_uri"] = context.Request.Query["redirect_uri"]
    })
    {
        RedirectUri = "/callback/login/edu"
    };

    await context.ChallengeAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, properties);
});

// Callback Endpoint to Handle Azure AD's Response and Issue Token
app.MapGet("/callback/login/{provider}", async (HttpContext context) =>
{
    var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
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

        var JWTSettingsConfig = builder.Configuration.GetSection("JWTSettings");

        // JWT settings
        var issuer = $"{context.Request.Scheme}://{context.Request.Host}";
        var audience = "resource-server-1";
        var secretKey = JWTSettingsConfig["SecretKey"];
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
