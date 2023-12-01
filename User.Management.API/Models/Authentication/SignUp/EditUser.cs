using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.SignUp
{
    public class EditUser
    {
        public string? Username { get; set; }
                
        public string? Email { get; set; }
        public string? Role { get; set; }
    }
}
