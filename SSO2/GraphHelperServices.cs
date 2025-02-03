using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Graph.Models;
namespace SSO2
{
    public static class GraphHelperServices
    {
        public static async Task SendEmail(HttpContext context, string title, string body, string[] recipients)
        {
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var tenantId = configuration["GraphHelper:TenantId"];
            var clientId = configuration["GraphHelper:ClientId"];
            var clientSecret = configuration["GraphHelper:ClientSecret"];
            var serviceAccount = configuration["GraphHelper:ServiceAccount"];
            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            GraphServiceClient _appClient = new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });

            var toRecipients = recipients.Select(email => new Recipient
            {
                EmailAddress = new EmailAddress { Address = email }
            }).ToList();

            var message = new Message
            {
                Subject = title,
                Body = new ItemBody
                {
                    ContentType = BodyType.Html,
                    Content = body
                },
                ToRecipients = toRecipients
            };

            var mailbody = new Microsoft.Graph.Users.Item.SendMail.SendMailPostRequestBody
            {
                Message = message,
                SaveToSentItems = false
            };

            try
            {
                // Send the email
                await _appClient.Users[serviceAccount]
                    .SendMail
                    .PostAsync(mailbody);
            }
            catch (Exception ex)
            {
                // Handle the exception as needed
                throw;
            }


        }
    }
}
