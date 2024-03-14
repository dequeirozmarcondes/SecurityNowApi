using System.ComponentModel.DataAnnotations;

namespace SecurityNowApi.DTOs
{
    public class LoginModel
    {
        [Required(ErrorMessage = "E-mail is required")]
        [EmailAddress(ErrorMessage = "Invalid E-mail!")]
        public string? Email { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
