using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OAuthNAuthZPoC.Models
{
    public class CachedUser
    {
        public string DisplayName { get; set; }
        public string Email { get; set; }
        public string Avatar { get; set; }
    }
}