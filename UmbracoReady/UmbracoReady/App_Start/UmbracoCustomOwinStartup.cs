using Microsoft.Owin;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Threading.Tasks;
using Umbraco.Core;
using Umbraco.Core.Security;
using Umbraco.Web.Security.Identity;
using UmbracoReady;
using UmbracoReady.App_Start;

//To use this startup class, change the appSetting value in the web.config called 
// "owin:appStartup" to be "UmbracoCustomOwinStartup"

[assembly: OwinStartup("UmbracoCustomOwinStartup", typeof(UmbracoCustomOwinStartup))]

namespace UmbracoReady
{
    /// <summary>
    /// A custom way to configure OWIN for Umbraco
    /// </summary>
    /// <remarks>
    /// The startup type is specified in appSettings under owin:appStartup - change it to "UmbracoCustomOwinStartup" to use this class
    /// 
    /// This startup class would allow you to customize the Identity IUserStore and/or IUserManager for the Umbraco Backoffice
    /// </remarks>
    public class UmbracoCustomOwinStartup
    {
        public void Configuration(IAppBuilder app)
        {
            //Configure the Identity user manager for use with Umbraco Back office

            // *** EXPERT: There are several overloads of this method that allow you to specify a custom UserStore or even a custom UserManager!            
            app.ConfigureUserManagerForUmbracoBackOffice(
                ApplicationContext.Current,
				//The Umbraco membership provider needs to be specified in order to maintain backwards compatibility with the 
				// user password formats. The membership provider is not used for authentication, if you require custom logic
				// to validate the username/password against an external data source you can create create a custom UserManager
				// and override CheckPasswordAsync
                global::Umbraco.Core.Security.MembershipProviderExtensions.GetUsersMembershipProvider().AsUmbracoMembershipProvider());
            
            //Ensure owin is configured for Umbraco back office authentication
            app
                .UseUmbracoBackOfficeCookieAuthentication(ApplicationContext.Current)
                .UseUmbracoBackOfficeExternalCookieAuthentication(ApplicationContext.Current);

            /* 
             * Configure external logins for the back office:
             * 
             * Depending on the authentication sources you would like to enable, you will need to install 
             * certain Nuget packages. 
             * 
             * For Google auth:					Install-Package UmbracoCms.IdentityExtensions.Google
             * For Facebook auth:					Install-Package UmbracoCms.IdentityExtensions.Facebook
             * For Microsoft auth:					Install-Package UmbracoCms.IdentityExtensions.Microsoft
             * For Azure ActiveDirectory auth:		Install-Package UmbracoCms.IdentityExtensions.AzureActiveDirectory
             * 
             * There are many more providers such as Twitter, Yahoo, ActiveDirectory, etc... most information can
             * be found here: http://www.asp.net/web-api/overview/security/external-authentication-services
             * 
             * For sample code on using external providers with the Umbraco back office, install one of the 
             * packages listed above to review it's code samples 
             *  
             */

            /*
             * To configure a simple auth token server for the back office:
             *             
             * By default the CORS policy is to allow all requests
             * 
             *      app.UseUmbracoBackOfficeTokenAuth(new BackOfficeAuthServerProviderOptions());
             *      
             * If you want to have a custom CORS policy for the token server you can provide
             * a custom CORS policy, example: 
             * 
             *      app.UseUmbracoBackOfficeTokenAuth(
             *          new BackOfficeAuthServerProviderOptions()
             *              {
             *             		//Modify the CorsPolicy as required
             *                  CorsPolicy = new CorsPolicy()
             *                  {
             *                      AllowAnyHeader = true,
             *                      AllowAnyMethod = true,
             *                      Origins = { "http://mywebsite.com" }                
             *                  }
             *              });
             */


            // Following code is for allowing the backoffice users to login using ReadyConnect (OpenIdConnect with sign-on using mobile app).

            var identityOptions 
                = new OpenIdConnectAuthenticationOptions
                    {
                        ClientId                    = "UmbracoReadyDemo",
                        Caption                     = "Umbraco Ready",
                        ResponseType                = "code id_token token",    // This corresponds to the Hybrid Flow outlined in oidc core spec 1.0.
                        Scope                       = "openid profile application.profile rso_rid",   // When rso_rid is absent, rso_idp is used.
                        SignInAsAuthenticationType = Constants.Security.BackOfficeExternalAuthenticationType,
                        Authority                   = "https://members.readysignon.com/",
                        RedirectUri                 = "http://localhost:5198/Umbraco",
                        PostLogoutRedirectUri       = "http://localhost:5198/Umbraco",
                    };

            // Configure BackOffice Account Link button and style
            identityOptions.ForUmbracoBackOffice("btn-openid", "fa-openid");    // More are avail at: https://fontawesome.com/
            identityOptions.Caption = "ReadyConnect";                           // Or any other name you like.

            // Give this middleware a unique type name
            identityOptions.AuthenticationType = "https://members.readysignon.com/";    

            // Configure AutoLinking, which allows Umbraco to automatically add a first-time
            // visitor to its backoffice database without prompting the user.
            identityOptions.SetExternalSignInAutoLinkOptions
                (
                    new ExternalSignInAutoLinkOptions(  autoLinkExternalAccount:    true, 
                                                        defaultUserGroups:          null, 
                                                        defaultCulture:             null)
                );

            // Here we customize two event handlers, one for transforming the claims recevied and another for 
            // making sure the IdP Url is set (as the authority uri) in the OpenIdConnect request so it becomes
            // easily accessible to the rest of the processing pipeline. The ReadySignOn mobile app uses the 
            // IdP Url to search for maching record(s) in its secure vault upong receving an authentication request.
            
            identityOptions.Notifications 
                = new OpenIdConnectAuthenticationNotifications
                    {
                        SecurityTokenValidated = ClaimsTransformer.GenerateUserIdentityAsync,       // See code of ClaimsTransformer class for details. 

                        RedirectToIdentityProvider = ctx =>
                        {
                            ctx.ProtocolMessage.IdentityProvider = identityOptions.Authority;       // The IdP will decide its own best url if this is not set here.
                            return Task.FromResult(0);
                        }
                    };

            app.UseOpenIdConnectAuthentication(identityOptions);    // Don't forget this line and updating the web.config with <add key="owin:appStartup" value="UmbracoCustomOwinStartup" />
        }

    }
}
