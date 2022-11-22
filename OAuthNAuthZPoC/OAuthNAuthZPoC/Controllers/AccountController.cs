using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace OAuthNAuthZPoC.Controllers
{
    public class AccountController : Controller
    {
      public void SignIn()
        {
            if(!Request.IsAuthenticated)
            {
                Request.GetOwinContext().Authentication.Challenge(
                    new Microsoft.Owin.Security.AuthenticationProperties { RedirectUri = "/" },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        public ActionResult SignOut()
        {
            if(Request.IsAuthenticated)
            {
                Request.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            }

            return RedirectToAction("Index", "Home");
        }
    }
}