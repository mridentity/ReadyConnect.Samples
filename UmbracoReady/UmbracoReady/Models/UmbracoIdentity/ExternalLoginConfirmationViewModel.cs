using System.ComponentModel.DataAnnotations;

namespace UmbracoReady.Models.UmbracoIdentity
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }
}
