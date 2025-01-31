
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Abstractions;
using System.Text.Json;
using SSO2;
using System.Net.Sockets;
using System.Net;
using OpenIddict.Client;


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

        options.AddRegistration(new OpenIddictClientRegistration
        {
            Issuer = new Uri(builder.Configuration["ArmyAzureAd:Authority"] ?? throw new InvalidOperationException("ArmyAzureAd:Authority is not configured.")),
            ClientId = builder.Configuration["ArmyAzureAd:ClientId"] ?? throw new InvalidOperationException("ArmyAzureAd:ClientId is not configured."),
            // I don't have a client secret
           // ClientSecret = builder.Configuration["ArmyAzureAd:ClientSecret"] ?? throw new InvalidOperationException("ArmyAzureAd:ClientSecret is not configured."),
            Scopes = { "openid", "profile", "email" },
            RedirectUri = new Uri("/SingleSignOn/callback/login/army", UriKind.Relative),
            ProviderName = "Army",
        });

        options.UseWebProviders()
            .AddMicrosoft(eduOptions =>
            {
                eduOptions.SetClientId(builder.Configuration["EDUAzureAd:ClientId"] ?? throw new InvalidOperationException("EDUAzureAd:ClientId is not configured."))
                          .SetClientSecret(builder.Configuration["EDUAzureAd:ClientSecret"] ?? throw new InvalidOperationException("EDUAzureAd:ClientSecret is not configured."))
                          .SetTenant(builder.Configuration["EDUAzureAd:TenantId"] ?? throw new InvalidOperationException("EDUAzureAd:TenantId is not configured."))
                          .SetRedirectUri("/SingleSignOn/callback/login/edu")
                          .SetProviderName("EDU"); // Set the provider name here
            })
           .AddGoogle(googleOptions =>
           {
               googleOptions.SetClientId(builder.Configuration["Google:ClientId"] ?? throw new InvalidOperationException("Google:ClientId is not configured."))
                       .SetClientSecret(builder.Configuration["Google:ClientSecret"] ?? throw new InvalidOperationException("Google:ClientSecret is not configured."))
                       .SetRedirectUri("/SingleSignOn/callback/login/google")
                       .SetProviderName("Google");
               googleOptions.AddScopes("email");
               googleOptions.AddScopes("profile");
           });

        options.AllowAuthorizationCodeFlow();

        options.UseAspNetCore()
               .EnableRedirectionEndpointPassthrough()
               .EnablePostLogoutRedirectionEndpointPassthrough();
      /*  options.AddEventHandler<OpenIddictClientEvents.PrepareAuthorizationRequestContext>(builder =>
      builder.UseInlineHandler(context =>
      {
          context.Request.CodeChallengeMethod = OpenIddictConstants.CodeChallengeMethods.Sha256;
          return default;
      }));*/
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        policy.WithOrigins(
               "https://localhost:3000",
               "https://apps-dev.armywarcollege.edu",
               "https://app.armywarcollege.edu"
           ) // Specify the allowed origin
             .AllowAnyHeader() // Allow all headers
              .AllowAnyMethod() // Allow all HTTP methods
              .AllowCredentials(); // Allow cookies or credentials
    });
});

// Step 5: Ensure authorization services are added
builder.Services.AddAuthorization();


var app = builder.Build();



app.UsePathBase("/SingleSignOnServer");

app.UseCors("CorsPolicy");

/*
app.Use(async (context, next) =>
{
    var authority = builder.Configuration["ArmyAzureAd:Authority"];
    Console.WriteLine($"Requesting OpenID Config: {authority}/.well-known/openid-configuration");

    using var client = new HttpClient();
    var response = await client.GetAsync($"{authority}/.well-known/openid-configuration");

    if (!response.IsSuccessStatusCode)
    {
        Console.WriteLine($" Failed to retrieve OpenID config. Status: {response.StatusCode}");
        string errorContent = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Response: {errorContent}");
    }
    else
    {
        string content = await response.Content.ReadAsStringAsync();
        Console.WriteLine($" OpenID Config Response: {content}");
    }

    await next();
});*/



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
    var pathBase = context.Request.PathBase.HasValue ? context.Request.PathBase.Value : "";

    if (buttonsToDisplay.Contains("army"))
    {
        buttonsHtml.Append($@"<button class=""btn"" onclick=""location.href='{pathBase}/login/army?redirect_uri={clientRedirectUri}'"">Log on Army</button>");
    }
    if (buttonsToDisplay.Contains("edu"))
    {
        buttonsHtml.Append($@"<button class=""btn"" onclick=""location.href='{pathBase}/login/edu?redirect_uri={clientRedirectUri}'"">Log on EDU</button>");
    }
    if (buttonsToDisplay.Contains("email"))
    {
        buttonsHtml.Append($@"<button class=""btn"" onclick=""location.href='{pathBase}/login/email?redirect_uri={clientRedirectUri}'"">Send Email Link</button>");
    }
    if (buttonsToDisplay.Contains("google"))
    {
        buttonsHtml.Append($@"<button class=""btn"" onclick=""location.href='{pathBase}/login/google?redirect_uri={clientRedirectUri}'"">Log on with Google</button>");
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
    var pathBase = context.Request.PathBase.HasValue ? context.Request.PathBase.Value : "";
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
                <form method=""post"" action=""{pathBase}/login/email?redirect_uri={clientRedirectUri}"">
                    <input type=""email"" name=""email"" placeholder=""Enter your email"" class=""input-field"" required />
                    <input type=""submit"" value=""Submit"" class=""btn"" />
                </form>
            </div>
        </body>
        </html>
    ");
});

app.MapGet("/setrefreshtoken", async (HttpContext context, ApplicationDbContext _context) =>
{
    // Retrieve the refresh token from cookies
    var refreshToken = context.Request.Cookies["refreshToken"];
    if (string.IsNullOrEmpty(refreshToken))
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Unauthorized: Missing refresh token.");
        return;
    }

    // Locate the refresh token in the database
    var appUser = _context.AppUsers.Include(r => r.RefreshTokens)
        .FirstOrDefault(u => u.RefreshTokens.Any(rt => rt.Token == refreshToken));

    if (appUser == null)
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Unauthorized: Invalid refresh token.");
        return;
    }

    var oldRefreshToken = appUser.RefreshTokens.SingleOrDefault(rt => rt.Token == refreshToken);

    // Check if the refresh token is active
    if (oldRefreshToken == null || !oldRefreshToken.IsActive)
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Unauthorized: Expired or /d refresh token.");
        return;
    }

    // Revoke the old refresh token
    oldRefreshToken.Revoked = DateTime.UtcNow;

    // Generate a new refresh token
    var newRefreshToken = UtilityClass.GenerateRefreshToken();
    appUser.RefreshTokens.Add(newRefreshToken);
    await _context.SaveChangesAsync();

    // Set the new refresh token as a secure, HttpOnly cookie
    var cookieOptions = new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.None,
        Expires = DateTime.UtcNow.AddDays(7)
    };
    context.Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

    // Generate a new access token
    JwtSecurityToken jwtToken = UtilityClass.GenerateAccessToken(context, appUser.Email, appUser.LoggedInUsing);

    var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);

    // Return the new access token
    var response = new { token = tokenString };
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsync(JsonSerializer.Serialize(response));
});

app.MapPost("/login/email", async (HttpContext context, ApplicationDbContext _context) =>
{
    try
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

        AppUser appUser = _context.AppUsers
            .Where(x => x.Email == email && x.LoggedInUsing == "email")
            .FirstOrDefault();

        if (appUser == null)
        {
            AppUser newAppUser = new AppUser
            {
                Email = email,
                LoggedInUsing = "email"
            };
            _context.AppUsers.Add(newAppUser);
            await _context.SaveChangesAsync();
        }

        JwtSecurityToken jwtToken = UtilityClass.GenerateAccessToken(context, email, "email");

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenString = tokenHandler.WriteToken(jwtToken);

        // Create the email content
        var serverUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        var redirectUri = $"{serverUrl}/callback/login/email?redirect_uri={clientRedirectUri}&token={tokenString}";

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

        //  using var httpClient = new HttpClient();
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
        };

        using var httpClient = new HttpClient(handler);

        // Add the X-API-KEY header
        httpClient.DefaultRequestHeaders.Add("X-API-KEY", "DthdAd-JGC3XdvHOctzG6WTf7p6-eeJtXcqN4i8w7Yc");
        // Send the email via POST request
        var response = await httpClient.PostAsync(
            "https://local.apps.armywarcollege.edu/registration/api/SendEmail",
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
            await context.Response.WriteAsync($"Failed to send email. Status code: {response.StatusCode}");

            
        }
    }
    catch (Exception ex)
    {
        // Log the exception (optional)
        Console.WriteLine($"Exception occurred: {ex.Message}");

        // Write the exception details to the response
        context.Response.ContentType = "text/html";
        context.Response.StatusCode = 500; // Set the status code explicitly
        await context.Response.WriteAsync($@"
            <h1>500 Internal Server Error</h1>
            <p>An error occurred while processing your request.</p>
            <p><strong>Message:</strong> {ex.Message}</p>
            <pre>{ex.StackTrace}</pre>
        ");
    }
});

app.MapGet("/login/google", async (HttpContext context) =>
{
    var properties = new AuthenticationProperties(new Dictionary<string, string>
    {
        [OpenIddictClientAspNetCoreConstants.Properties.ProviderName] = "Google",
        ["redirect_uri"] = context.Request.Query["redirect_uri"]
    })
    {
        RedirectUri = "/callback/login/google"
    };

    await context.ChallengeAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, properties);
});

app.MapGet("/callback/login/email", async (HttpContext context, ApplicationDbContext _context) =>
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

        var email = principal.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        var loggedInUsing = principal.FindFirstValue("custom:loggedInUsing");

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(loggedInUsing))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Bad Request: Missing required claims.");
            return;
        }

        var appUser = _context.AppUsers.FirstOrDefault(x => x.Email == email && x.LoggedInUsing == loggedInUsing);

        if (appUser == null)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Not Found: User not found.");
            return;
        }

        var newRefreshToken = UtilityClass.GenerateRefreshToken();
        appUser.RefreshTokens.Add(newRefreshToken);
        await _context.SaveChangesAsync();



        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            Expires = DateTime.UtcNow.AddDays(7),
            SameSite = SameSiteMode.None,
            
        };


        context.Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
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
app.MapGet("/callback/login/{provider}", async (HttpContext context, ApplicationDbContext _context) =>
{
    var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    if (result.Succeeded)
    {
        var provider = context.Request.RouteValues["provider"]?.ToString()?.ToLower();
        string email;
        if (provider == "google")
        {
            // Google-specific claim for email
            email = result.Principal.FindFirstValue("email") ??
                    result.Principal.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        }
        else
        {
            // Standard claim for email
            email = result.Principal.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        }

        if (email == null)
        {
            await context.Response.WriteAsync("Email claim not found.");
            return;
        }

        JwtSecurityToken jwtToken = UtilityClass.GenerateAccessToken(context, email, provider);

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenString = tokenHandler.WriteToken(jwtToken);

        // Retrieve the client-specified redirect URI from the login endpoint
        var clientRedirectUri = result.Properties?.Items["redirect_uri"];

        // Redirect to the client with the token in the query string
        var redirectUri = $"{clientRedirectUri}?token={tokenString}";

        AppUser appUser = _context.AppUsers
        .Where(x => x.Email == email && x.LoggedInUsing == provider)
        .FirstOrDefault();

        if (appUser == null)
        {
            appUser = new AppUser
            {
                Email = email,
                LoggedInUsing = provider
            };
            _context.AppUsers.Add(appUser);
            await _context.SaveChangesAsync();
        }
        var newRefreshToken = UtilityClass.GenerateRefreshToken();
        appUser.RefreshTokens.Add(newRefreshToken);
        await _context.SaveChangesAsync();

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.None,
            Secure = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };

        context.Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
        context.Response.Redirect(redirectUri);
    }
    else
    {
        await context.Response.WriteAsync("Authentication failed.");
    }
});

app.Run();
