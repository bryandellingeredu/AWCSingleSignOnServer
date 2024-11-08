namespace SSO2
{
    using Microsoft.Extensions.DependencyInjection;
    using OpenIddict.Abstractions;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public static class OpenIddictSeeder
    {
        public static async Task SeedAsync(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            // Define the scopes for OpenID Connect
            var scopes = new List<OpenIddictScopeDescriptor>
        {
            new OpenIddictScopeDescriptor
            {
                Name = OpenIddictConstants.Scopes.OpenId,
                DisplayName = "OpenID Connect access",
                Resources = { "resource-server-1" }
            },
            new OpenIddictScopeDescriptor
            {
                Name = OpenIddictConstants.Scopes.Profile,
                DisplayName = "User profile access",
                Resources = { "resource-server-1" }
            },
            new OpenIddictScopeDescriptor
            {
                Name = OpenIddictConstants.Scopes.Email,
                DisplayName = "Email access",
                Resources = { "resource-server-1" }
            }
        };

            // Ensure each scope is created if it doesn't already exist
            foreach (var scopeDescriptor in scopes)
            {
                if (await scopeManager.FindByNameAsync(scopeDescriptor.Name) == null)
                {
                    await scopeManager.CreateAsync(scopeDescriptor);
                }
            }

            // Register the client application with authorization code flow permissions
            if (await applicationManager.FindByClientIdAsync("new-client-id") == null)
            {
                var clientDescriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = "new-client-id",
                    DisplayName = "React Client",
                    RedirectUris = { new Uri("http://localhost:3000/callback") },
                    Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code
                }
                };

                // Add permissions for each scope
                foreach (var scopeDescriptor in scopes)
                {
                    clientDescriptor.Permissions.Add($"{OpenIddictConstants.Permissions.Prefixes.Scope}{scopeDescriptor.Name}");
                }

                await applicationManager.CreateAsync(clientDescriptor);
            }
        }
    }
}
