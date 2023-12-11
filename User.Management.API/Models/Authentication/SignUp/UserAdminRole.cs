using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace User.Management.API.Models.Authentication.SignUp
{
    [Table("UserAdminRole")]
    public class UserAdminRole
    {
        [Required]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int ID { get; set; }
        [Required]
        public string UserName { get; set; }

        [Required]
        public string UserEmail { get; set; }
        [Required]
        public string AdminUserId { get; set; }
        public string AdminUserName { get; set; }
        
    }
}
