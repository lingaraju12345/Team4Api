using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using User.Management.API.Models.Authentication;
using User.Management.API.Models.Authentication.SignUp;

namespace User.Management.API.Models
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        public IQueryable<IdentityUser> GetUsersByRoleId(string roleId)
        { var usersInRole = from userRole in UserRoles
                            join user in Users on userRole.UserId 
                            equals user.Id where userRole.RoleId == roleId select user;
            
            return usersInRole;
        }

        public DbSet<LogDetails> LogDetails { get; set; }
        public DbSet<UserAdminRole> UserAdminRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);


        }

        private static void SeedRoles(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData
                (
                new IdentityRole() { Name = "SuperAdmin", ConcurrencyStamp = "1",NormalizedName= "SuperAdmin" },
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "2", NormalizedName = "Admin" },
                 new IdentityRole() { Name = "Users", ConcurrencyStamp = "3", NormalizedName = "Users" }

                );
        }
    }
}
