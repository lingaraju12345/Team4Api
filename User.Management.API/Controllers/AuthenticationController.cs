using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.API.Models;
using User.Management.API.Models.Authentication;
using User.Management.API.Models.Authentication.Login;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Services;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {

        public UserManager<IdentityUser> _userManager;
        public SignInManager<IdentityUser> _signInManager;
        public RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, IEmailService emailService,
            SignInManager<IdentityUser> signInManager, IConfiguration configuration, ApplicationDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _configuration = configuration;
            _context = context;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            // Checking whether SuperAdmin users exist
            var superAdminUsers = _context.GetUsersByRoleId("77724232-4b63-4fd7-a3d0-215cd4881aa9").Any();

            // If there are SuperAdmin users, prevent registration with SuperAdmin role
            if (superAdminUsers && registerUser.Role == "SuperAdmin")
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "SuperAdmin registration not allowed!" });
            }

            // Checking whether User Exist 
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists!" });
            }

            // If role exists, proceed with registration
            if (await _roleManager.RoleExistsAsync(registerUser.Role))
            {
                // Adding the User in the database
                IdentityUser user = new()
                {
                    
                    Email = registerUser.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = registerUser.Username,
                    TwoFactorEnabled = true
                };

                // Rest of the code for user registration...
                var result = await _userManager.CreateAsync(user, registerUser.Password);

                // Adding role to the user....
                await _userManager.AddToRoleAsync(user, registerUser.Role);

                // Adding admin to user....
                var adminUser = await _userManager.FindByNameAsync(registerUser.AdminUserName);
                if (adminUser != null)
                {
                    var useradminrole = new UserAdminRole
                    {
                        UserName = registerUser.Username,
                        UserEmail = registerUser.Email,
                        AdminUserId = adminUser.Id,
                        AdminUserName = adminUser.UserName
                    };
                    _context.UserAdminRoles.Add(useradminrole);
                    await _context.SaveChangesAsync();
                }

                // Adding Token to Verify the email....
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var verificationMessage = $" <div style='font-size:20px;'> Welcome to Featuremesh Application. </div><br>" +
                    $"<br> " +
                    $"Click on the below link to verify your email:<br>" +
                    $" <a href='{confirmationLink}'>{confirmationLink}</a>";
                var message = new Message(new string[] { user.Email! }, "Email verification link", verificationMessage);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"User created & Email Sent to {user.Email} SuccessFully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "This Role Does not Exist." });
            }
        }



        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    var content = "<div style='font-family:Arial; text-align:center; font-size: 40px;'> Welcome to Featuremesh Application. </div> <br/>" +
                        $"<br/><br/><br/><br/>" +
                        $" <div style ='font-family:Times New Roman; text-align:center; font-size: 24px;'> Your Email has been verified successfully.</div><br/><br/><br/>" +
                        $" <div style='font-family:Times New Roman; text-align:center; font-size:20px;'> Click on the link to start using the application.</div>" +
                        $" <div style='text-align: center;'><a href='https://green-sky-03dfcc510.4.azurestaticapps.net'>Explore the application</a></div>";

                    return Content(content, "text/html");
                }
            }
            return Content("<div style='color:red; font-family:Times New Roman; font-size:26px;'> This User does not exist</div> ", "text/html");
        }




        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user == null)
            {
                return Unauthorized(new Response { Status = "Error", Message = "Invalid username or password." });
            }
            // Check if the entered password is correct
            var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginModel.Password);
            if (!isPasswordValid)
            {
                return Unauthorized(new Response { Status = "Error", Message = "Invalid username or password." });
            }
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                                new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
            }
            return StatusCode(StatusCodes.Status200OK,
         new Response { Status = "Success", Message = "Login successful." });
        }





        [HttpGet("AllUsers")]
        public IActionResult GetAll()
        {
            var users = _userManager.Users.ToList();
            var dtousers = users.Select(p => new
            {
                ID = p.Id,
                Name = p.UserName,
                Email = p.Email,
                Role = _userManager.GetRolesAsync(p).Result,
                Admin = _context.UserAdminRoles.Where(r => r.UserEmail == p.Email).Select(r => r.AdminUserName).FirstOrDefault()
            });

            return Ok(dtousers);
        }
        [HttpGet("AdminUsers")]
        public IActionResult AdminUsers()
        {
            var usersInRole = _context.GetUsersByRoleId("0c206cb8-2fb3-4e83-b4f5-caeddd6c8244").ToList();
            var Admins = usersInRole.Select(p => new
            {
                Name = p.UserName
            });
            return Ok(Admins);
        }

        [HttpGet("SuperAdminExists")]
        public IActionResult SuperAdminExists()
        {
            var superAdminExists = _context.GetUsersByRoleId("77724232-4b63-4fd7-a3d0-215cd4881aa9").Any();

            return Ok(superAdminExists);
        }

        [HttpDelete("Delete")]
        public async Task<IActionResult> Delete(string Email)
        {
            var userExist = await _userManager.FindByEmailAsync(Email);
            if (userExist == null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "User not found." });
            }
            var result = await _userManager.DeleteAsync(userExist);

            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "User deleted successfully." });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Failed to delete user." });
            }
        }

        [HttpPut("EditUser")]
        public async Task<IActionResult> EditUser([FromBody] EditUser editUser)
        {

            // Check if the provided email exists
            var user = await _userManager.FindByEmailAsync(editUser.Email);

            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "User not found." });
            }

            // Update user details
            user.UserName = editUser.Username;
            user.Email = editUser.Email;

            // Check if the role exists
            var roleExists = await _roleManager.RoleExistsAsync(editUser.Role);
            if (!roleExists)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "This Role Doesnot Exist." });
            }

            // Remove existing roles and add the new role
            var currentRoles = await _userManager.GetRolesAsync(user);
            await _userManager.RemoveFromRolesAsync(user, currentRoles);
            await _userManager.AddToRoleAsync(user, editUser.Role);

            //Admin user
            var adminUser = await _userManager.FindByNameAsync(editUser.Admin);
            if (adminUser != null)
            {
                // Check if a UserAdminRole already exists for the user
                var existingUserAdminRole = _context.UserAdminRoles
                    .SingleOrDefault(uar => uar.UserEmail == editUser.Email);
                if (existingUserAdminRole != null)
                {


                    existingUserAdminRole.AdminUserId = adminUser.Id;
                    existingUserAdminRole.AdminUserName = adminUser.UserName;
                }

                await _context.SaveChangesAsync();
            }
            // Update user in the database
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "User updated successfully." });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Failed to update user." });
            }
        }

        [HttpGet("GetUserByEmail")]
        public async Task<IActionResult> GetUserByEmail(string email)
        {
            var userEmail = await _userManager.FindByEmailAsync(email);

            if (userEmail != null)
            {
                var userRoles = await _userManager.GetRolesAsync(userEmail);

                var dtoUser = new
                {
                    ID = userEmail.Id,
                    Name = userEmail.UserName,
                    Email = userEmail.Email,
                    Role = _userManager.GetRolesAsync(userEmail).Result,
                    Admin = _context.UserAdminRoles.Where(r => r.UserEmail == email).Select(r => r.AdminUserName).FirstOrDefault()
                };

                return Ok(dtoUser);
            }
            else
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "User not found." });
            }
        }


        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP([FromBody] Loginotp loginotp)
        {
            try
            {
                var userLogin = await _userManager.FindByNameAsync(loginotp.username);

                if (userLogin == null)
                {
                    return StatusCode(StatusCodes.Status404NotFound,
                        new Response { Status = "Failed to Login", Message = $"User not found" });
                }

                // Retrieve the stored OTP from the token sent via email
                string storedOTP = loginotp.code; // Assuming loginotp.code contains the token sent via email

                // Compare the entered token with the stored OTP
                var isOTPValid = await _userManager.VerifyTwoFactorTokenAsync(userLogin, "Email", storedOTP);

                if (isOTPValid)

                {
                    var userRoles = await _userManager.GetRolesAsync(userLogin);

                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, userLogin.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtToken = GetToken(authClaims);

                    // Log the successful login
                    var logDetails = new LogDetails
                    {
                        Username = userLogin.UserName,
                        Email = userLogin.Email,
                        LoginInfo = DateTime.Now,
                    };
                    _context.LogDetails.Add(logDetails);
                    await _context.SaveChangesAsync();

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo,
                        role = userRoles.Contains("SuperAdmin") ? "SuperAdmin" : "NotSuperAdmin"
                    });

                }
                else
                {
                    // OTP doesn't match, return an error
                    return StatusCode(StatusCodes.Status401Unauthorized,
                        new Response { Status = "Failed to Login", Message = $"Invalid verification Code" });
                }
            }
            catch (Exception ex)
            {
                // Log the exception for debugging purposes
                Console.WriteLine($"Exception: {ex.Message}");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Internal Server Error" });
            }
        }

        [HttpGet("LogDetails")]
        public async Task<IActionResult> GetLogDetails()
        {
            var logDetails = await _context.LogDetails.ToListAsync();
            var log = logDetails.Select(p => new
            {
                Name = p.Username,
                Email = p.Email,
                DateTime = p.LoginInfo
            });
            return Ok(log);
        }

        [HttpGet("LogDetailsByEmail")]
        public async Task<IActionResult> GetLogByEmail(string email)
        {
            try
            {
                var logDetailsByEmail = await _context.LogDetails
                    .Where(log => log.Email == email)
                    .ToListAsync();
                if (logDetailsByEmail == null || logDetailsByEmail.Count == 0)
                {
                    return StatusCode(StatusCodes.Status404NotFound,
                        new Response { Status = "Error", Message = "No log details found for the specified email." });
                }
                var log = logDetailsByEmail.Select(p => new
                {
                    Name = p.Username,
                    Email = p.Email,
                    DateTime = p.LoginInfo
                });
                return Ok(log);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: {ex.Message}");
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "Internal Server Error" });
            }
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(2),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}