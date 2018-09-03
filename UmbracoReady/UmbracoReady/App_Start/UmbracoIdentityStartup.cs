using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using UmbracoIdentity;
using UmbracoReady.Models.UmbracoIdentity;
using UmbracoReady;
using Owin;
using Umbraco.Web;
using Umbraco.Web.Security.Identity;
using UmbracoIdentity.Models;
using Umbraco.Core;
using Umbraco.Core.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using UmbracoReady.App_Start;
using System.Threading.Tasks;
using System.Configuration;

[assembly: OwinStartup("UmbracoIdentityStartup", typeof(UmbracoIdentityStartup))]

namespace UmbracoReady
{
   
    /// <summary>
    /// OWIN Startup class for UmbracoIdentity 
    /// </summary>
    public class UmbracoIdentityStartup : UmbracoDefaultOwinStartup
    {
        /// <summary>
        /// Configures services to be created in the OWIN context (CreatePerOwinContext)
        /// </summary>
        /// <param name="app"/>
        protected override void ConfigureServices(IAppBuilder app)
        {
            base.ConfigureServices(app);

            //Single method to configure the Identity user manager for use with Umbraco
            app.ConfigureUserManagerForUmbracoMembers<UmbracoApplicationMember>();

            //Single method to configure the Identity user manager for use with Umbraco
            app.ConfigureRoleManagerForUmbracoMembers<UmbracoApplicationRole>();
        }

        /// <summary>
        /// Configures middleware to be used (i.e. app.Use...)
        /// </summary>
        /// <param name="app"/>
        protected override void ConfigureMiddleware(IAppBuilder app)
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

            //Ensure owin is configured for Umbraco back office authentication. If you have any front-end OWIN
            // cookie configuration, this must be declared after it.
            app
                .UseUmbracoBackOfficeCookieAuthentication(ApplicationContext, PipelineStage.Authenticate)
                .UseUmbracoBackOfficeExternalCookieAuthentication(ApplicationContext, PipelineStage.Authenticate);

            // Enable the application to use a cookie to store information for the 
            // signed in user and to use a cookie to temporarily store information 
            // about a user logging in with a third party login provider 
            // Configure the sign in cookie
            app.UseCookieAuthentication(new FrontEndCookieAuthenticationOptions
            {
                SlidingExpiration = true,   // We prefer to have the sliding expiration enabled.

                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user 
                    // logs in. This is a security feature which is used when you 
                    // change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator
                        .OnValidateIdentity<UmbracoMembersUserManager<UmbracoApplicationMember>, UmbracoApplicationMember, int>(
                            TimeSpan.FromMinutes(30),
                            (manager, user) => user.GenerateUserIdentityAsync(manager),
                            UmbracoIdentity.IdentityExtensions.GetUserId<int>)
                }
            }, PipelineStage.Authenticate);

            ConfigureOpenIdForBackOffice(app);

            ConfigureOpenIdForFrontEnd(app);

            //Lasty we need to ensure that the preview Middleware is registered, this must come after
            // all of the authentication middleware:
            app.UseUmbracoPreviewAuthentication(ApplicationContext, PipelineStage.Authorize);
        }

        private static void ConfigureOpenIdForBackOffice(IAppBuilder app)
        {

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
                    ClientId = "UmbracoBackOfficeReadyDemo",       // This client has already been registered. You may register more via https://members.readysignon.com
                    Caption = "ReadyConnect",                // Text used for displaying this sign-in option on the login page.
                    ResponseType = "code id_token token",    // This corresponds to the Hybrid Flow outlined in oidc core spec 1.0.
                    Scope = "openid profile application.profile rso_idp rso_rid",   // When rso_rid is absent, rso_idp is used.
                    SignInAsAuthenticationType = Umbraco.Core.Constants.Security.BackOfficeExternalAuthenticationType,
                    Authority = "https://members.readysignon.com/",
                    RedirectUri = Properties.Settings.Default.MAIN_SITE_BASE_URL + "/Umbraco",      // This cannot be change unless you use a different client registration created at https://members.readysignon.com
                    PostLogoutRedirectUri = Properties.Settings.Default.MAIN_SITE_BASE_URL + "/Umbraco"
                };

            // Configure BackOffice Account Link button and style
            identityOptions.ForUmbracoBackOffice("btn-openid", "fa-openid");    // More are avail at: https://fontawesome.com/

            // Give this middleware a unique type name
            identityOptions.AuthenticationType = identityOptions.Authority;   // For some reason this is required to be the same as the authority.

            ConfigureIdentityCreationAndCustomHandlers(app, identityOptions);
        }

        private static void ConfigureOpenIdForFrontEnd(IAppBuilder app)
        {
            // Uncomment the following lines to enable logging in with third party login providers

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            //app.UseMicrosoftAccountAuthentication(
            //  clientId: "",
            //  clientSecret: "");

            //app.UseTwitterAuthentication(
            //  consumerKey: "",
            //  consumerSecret: "");

            //app.UseFacebookAuthentication(
            //  appId: "",
            //  appSecret: "");

            //app.UseGoogleAuthentication(
            //  clientId: "",
            //  clientSecret: ""); 

            var identityOptions
                = new OpenIdConnectAuthenticationOptions
                {
                    ClientId = "UmbracoFrontEndReadyDemo",       // This client has already been registered. You may register more via https://members.readysignon.com
                    Caption = "ReadyConnect",                // Text used for displaying this sign-in option on the login page.
                    ResponseType = "code id_token token",    // This corresponds to the Hybrid Flow outlined in oidc core spec 1.0.
                    Scope = "openid profile application.profile rso_idp rso_rid",   // When rso_rid is absent, rso_idp is used.
                    SignInAsAuthenticationType = DefaultAuthenticationTypes.ExternalCookie,
                    Authority = "https://members.readysignon.com/",
                    RedirectUri = Properties.Settings.Default.MAIN_SITE_BASE_URL,      // This shouldn't be changed if you're running this code locally unless you want to register your own client application at https://members.readysignon.com
                    PostLogoutRedirectUri = Properties.Settings.Default.MAIN_SITE_BASE_URL
                };

            // Give this middleware a unique type name
            identityOptions.AuthenticationType = "readyconnectsvc_for_umbraco_fe";

            ConfigureIdentityCreationAndCustomHandlers(app, identityOptions);
        }

        private static void ConfigureIdentityCreationAndCustomHandlers(IAppBuilder app, OpenIdConnectAuthenticationOptions identityOptions)
        {
            // Configure AutoLinking, which allows Umbraco to automatically add a first-time
            // visitor to its database without prompting the user.
            identityOptions.SetExternalSignInAutoLinkOptions
                (
                    new ExternalSignInAutoLinkOptions(autoLinkExternalAccount: true,
                                                        defaultUserGroups: null,
                                                        defaultCulture: null)
                );

            // Here we customize two event handlers, one for transforming the claims recevied and another for 
            // making sure the IdP Url is set (as the authority uri) in the OpenIdConnect request so it becomes
            // easily accessible to the rest of the processing pipeline. The ReadySignOn mobile app uses the 
            // IdP Url to search for maching record(s) in its secure vault upong receving an authentication request.

            identityOptions.Notifications
                = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = ClaimsTransformer.GenerateUserIdentityAsync,       // See code of ClaimsTransformer class for details. 

                    RedirectToIdentityProvider = n =>
                    {
                        n.ProtocolMessage.IdentityProvider = identityOptions.Authority;       // The IdP will decide its own best url if this is not set here.
                        return Task.FromResult(0);
                    }
                };

            app.UseOpenIdConnectAuthentication(identityOptions);    // Don't forget this line and updating the web.config with <add key="owin:appStartup" value="UmbracoCustomOwinStartup" />
        }
    }
}

