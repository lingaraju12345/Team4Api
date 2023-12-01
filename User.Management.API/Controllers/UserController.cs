//using MailKit.Security;
//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Mvc;
//using MimeKit;
//using MimeKit.Text;
//using User.Management.API.Models.Authentication.SignUp;
//using User.Management.API.Repository;

//namespace User.Management.API.Controllers
//{
//    [Route("api/[controller]")]
//    [ApiController]
//    public class UserController : ControllerBase
//    {
//        IUserRepository<RegisterUser> UserRepository;
//        public UserController(IUserRepository<RegisterUser> UserRepository)
//        {
//            this.UserRepository = UserRepository;
            
//        }
//        [HttpGet("AllUsers")]
//        public IActionResult GetAll()
//        {
//            var users = UserRepository.GetAll();

//            var dtousers = users.Select(p => new
//            {
//                ID = p.Id,
//                Name = p.Username,
//                Email = p.Email,
//                RoleID = p.Role

//            }) ;
//            return Ok(dtousers);
//        }



//    }
//}
