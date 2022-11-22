using Microsoft.Owin;
using Owin;
using System;

[assembly: OwinStartup(typeof(OAuthNAuthZPoC.Startup))]

namespace OAuthNAuthZPoC
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
