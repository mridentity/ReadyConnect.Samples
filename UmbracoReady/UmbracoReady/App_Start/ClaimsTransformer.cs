using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace UmbracoReady.App_Start
{
    public class ClaimsTransformer
    {
        public static async Task GenerateUserIdentityAsync(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var identityUser 
                = new ClaimsIdentity(   notification.AuthenticationTicket.Identity.Claims,
                                        notification.AuthenticationTicket.Identity.AuthenticationType,
                                        ClaimTypes.Name,
                                        ClaimTypes.Role
                                    );

            var newIdentityUser 
                = new ClaimsIdentity(   identityUser.AuthenticationType,
                                        ClaimTypes.GivenName, 
                                        ClaimTypes.Role
                                    );

            newIdentityUser.AddClaim(identityUser.FindFirst(ClaimTypes.NameIdentifier));

            // Get additional claims from UserInfo endpoint.
            var userInfoClient 
                = new UserInfoClient(new Uri(notification.Options.Authority + "/connect/userinfo").ToString() );

            var userInfo 
                = await userInfoClient.GetAsync(notification.ProtocolMessage.AccessToken);

            newIdentityUser.AddClaims(userInfo.Claims);

            // Ensure the required ClaimTypes.Email is present. You may need to tweak this block
            // of code a bit if you're trying to connect to a different identity provider other than
            // ReadyConnect + ReadySignOn.
            if (newIdentityUser.FindFirst(ClaimTypes.Email) == null)
            {
                var emailClaim 
                    = newIdentityUser.FindFirst("email") ?? 
                        (identityUser.FindFirst(ClaimTypes.Email) ?? 
                            (identityUser.FindFirst(ClaimTypes.Name) ?? identityUser.FindFirst("name") )
                        );

                newIdentityUser.AddClaim(new Claim(ClaimTypes.Email, emailClaim.Value));
            }

            notification.AuthenticationTicket 
                = new AuthenticationTicket(newIdentityUser, notification.AuthenticationTicket.Properties);
        }
    }
}