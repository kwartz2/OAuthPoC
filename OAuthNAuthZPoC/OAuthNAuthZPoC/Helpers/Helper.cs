using Microsoft.Graph;
using OAuthNAuthZPoC.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace OAuthNAuthZPoC.Helpers
{
    public static class Helper
    {
        public static async Task<CachedUser> GetUserDetailsAsync(string accessToken)
        {
            var myClient = new GraphServiceClient(
                new DelegateAuthenticationProvider(
                    async (requestMessage) =>
                    {
                        requestMessage.Headers.Authorization =
                          new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                    }));

            var user = await myClient.Me.Request()
                .Select(u => new
                {
                    u.DisplayName,
                    u.Mail,
                    u.UserPrincipalName
                })
                .GetAsync();

            return new CachedUser
            {
                Avatar = string.Empty,
                DisplayName = user.DisplayName,
                Email = string.IsNullOrEmpty(user.Mail) ?
                user.UserPrincipalName : user.Mail
            };
        }
    }
}