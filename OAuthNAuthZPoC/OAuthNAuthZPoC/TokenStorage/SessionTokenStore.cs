using Microsoft.Identity.Client;
using Newtonsoft.Json;
using OAuthNAuthZPoC.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Web;

namespace OAuthNAuthZPoC.TokenStorage
{
    public class SessionTokenStore
    {
        private static readonly ReaderWriterLockSlim sessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        private HttpContext httpContext = null;
        private string tokenCacheKey = string.Empty;
        private string userCacheKey = string.Empty;

        public SessionTokenStore(ITokenCache tokenCache, HttpContext context, ClaimsPrincipal user)
        {
            httpContext = context;

            if(tokenCache != null)
            {
                tokenCache.SetBeforeAccess(BeforeAccessNotification);
                tokenCache.SetBeforeAccess(AfterAccessNotification);
            }

            var userId = GetUsersUniqueId(user);
            tokenCacheKey = $"{userId}_TokenCache";
            userCacheKey = $"{userId}_UserCache";
        }

        public bool HasData()
        {
            return (httpContext.Session[tokenCacheKey] != null &&
                ((byte[])httpContext.Session[tokenCacheKey]).Length > 0);
        }

        public void Clear()
        {
            sessionLock.EnterWriteLock();

            try 
            {
                httpContext.Session.Remove(tokenCacheKey);
            }
            finally
            {
                sessionLock.ExitWriteLock();
            }
        }

        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            sessionLock.EnterReadLock();

            try 
            { 
                args.TokenCache.DeserializeMsalV3((byte[])httpContext.Session[tokenCacheKey]);
            }
            finally
            {
                sessionLock.ExitReadLock();
            }
        }

        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            if(args.HasStateChanged)
            {
                sessionLock.EnterReadLock();

                try
                {
                    //Store the serialized cache in the sessions
                    httpContext.Session[tokenCacheKey] = args.TokenCache.SerializeMsalV3();
                }
                finally
                {
                    sessionLock.ExitReadLock();
                }
            }
        }

        public void SaveUserDetails(CachedUser user)
        {
            sessionLock.EnterWriteLock();
            httpContext.Session[userCacheKey] = JsonConvert.SerializeObject(user);
            sessionLock.ExitWriteLock();
        }

        public CachedUser GetUserDetails()
        {
            sessionLock.EnterReadLock();
            var cachedUser = JsonConvert.DeserializeObject<CachedUser>((string)httpContext.Session[userCacheKey]);
            sessionLock.ExitReadLock();
            return cachedUser;
        }

        public string GetUsersUniqueId(ClaimsPrincipal user)
        {
            //Combine the user's object ID with their tenant ID

            if(user != null)
            {
                var userObjectId = user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value ??
                    user.FindFirst("old").Value;

                var userTenantId = user.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value ??
                    user.FindFirst("tid").Value;

                if (!string.IsNullOrEmpty(userObjectId) && !string.IsNullOrEmpty(userTenantId))
                {
                    return $"{userObjectId}.{userTenantId}";
                }
            }

            return null;
        }
    }
}