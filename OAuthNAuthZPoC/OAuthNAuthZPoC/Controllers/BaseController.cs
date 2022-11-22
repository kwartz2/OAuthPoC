using OAuthNAuthZPoC.Models;
using System.Collections.Generic;
//using OAuthNAuthZPoC.TokenStorage;
using Microsoft.Owin.Security.Cookies;
using System.Web.Mvc;
using System.Security.Claims;

namespace OAuthNAuthZPoC.Controllers
{
    public abstract class BaseController : Controller
    {
        // GET: Base
        protected void Flash(string message, string debug = null)
        {
            var alerts = TempData.ContainsKey(Alert.AlertKey) ?
                (List<Alert>)TempData[Alert.AlertKey] :
                new List<Alert>();

            alerts.Add(new Alert
            {
                Message = message,
                Debug = debug
            });
            TempData[Alert.AlertKey] = alerts;
        }
    }

  
}