using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using User.Management.API.Models.Authentication.SignUp;

namespace User.Management.API.Models
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        

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
