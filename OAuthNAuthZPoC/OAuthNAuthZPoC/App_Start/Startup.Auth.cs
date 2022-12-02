using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Configuration;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using OAuthNAuthZPoC.TokenStorage;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using OAuthNAuthZPoC.Helpers;
using Microsoft.IdentityModel.Logging;

namespace OAuthNAuthZPoC
{
    public partial class Startup
    {
        private static string appId = ConfigurationManager.AppSettings["ida:AppId"];
        private static string appSecret = ConfigurationManager.AppSettings["ida:AppSecret"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        private static string scopes = ConfigurationManager.AppSettings["ida:AppScopes"];

        public void ConfigureAuth(IAppBuilder app)
        {
            IdentityModelEventSource.ShowPII = true;
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = appId,
                    Authority = "https://login.microsoftonline.com/common/v2.0",
                    Scope = $"openid email profile offline_access {scopes}",
                    RedirectUri = redirectUri,
                    PostLogoutRedirectUri = redirectUri,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        //for demo purposes only
                        ValidIssuer = "false",

                        //ValidIssuer = true.ToString(),
                        //IssuerValidator = (issuer, token, tvp) =>
                        //{
                        //    if (MyCustomTenantValidation(issuer))
                        //    {
                        //        return issuer;
                        //    }
                        //    else
                        //    {
                        //        throw new SecurityTokenInvalidIssuerException("Invalid Issuer");
                        //    }
                        //}
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailedAsync,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceivedAsync
                    }
                }
            ) ;

        }

        private static Task OnAuthenticationFailedAsync(AuthenticationFailedNotification<OpenIdConnectMessage,
            OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            string redirect = $"/Home/Error?message={notification.Exception.Message}";
            if (notification.ProtocolMessage != null && !string.IsNullOrEmpty(notification.ProtocolMessage.ErrorDescription))
            {
                redirect += $"&debug={notification.ProtocolMessage.ErrorDescription}";
            }
            notification.Response.Redirect(redirect);
            return Task.FromResult(0);
        }
        //ConfidentialClientApplication wraps the default user token cache with the SessionTokenStore class.
        //The MSAL library will handle the logic of storing the tokens and refreshing it when needed.
        //User details obtained from Microsoft Graph is passed to the sessionTokenStore object to store in the sessions.
        // The OWIN middleware to complete the authentication process.
        private async Task OnAuthorizationCodeReceivedAsync(AuthorizationCodeReceivedNotification notification)
        {
            notification.HandleCodeRedemption();

            var idClient = ConfidentialClientApplicationBuilder.Create(appId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(appSecret)
                .Build();

            var signedInUser = new ClaimsPrincipal(notification.AuthenticationTicket.Identity);
            var tokenStore = new SessionTokenStore(idClient.UserTokenCache, HttpContext.Current, signedInUser);
            //string message;
            //string debug;

            try
            {
                string[] scope = scopes.Split(' ');

                var result = await idClient.AcquireTokenByAuthorizationCode(
                    scope, notification.Code).ExecuteAsync();

                var userDetails = await Helper.GetUserDetailsAsync(result.AccessToken);

                tokenStore.SaveUserDetails(userDetails);
                notification.HandleCodeRedemption(null, result.IdToken);

                //message = "User info retrieved.";
                //debug = $"User: {userDetails.DisplayName}, Email: {userDetails.Email}";
            }
            catch (MsalException ex)
            {
                string message = "AcquireTokenByAuthorizationCodeAsync threw an exceoption";
                notification.HandleCodeRedemption();
                notification.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
                //debug = ex.Message;
            }
            catch (Microsoft.Graph.ServiceException ex)
            {
                string message = "GetUserDetailsAsync threw an exception";
                notification.HandleResponse();
                notification.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
            }

           
        }
    }
}