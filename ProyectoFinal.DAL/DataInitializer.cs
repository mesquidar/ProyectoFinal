using System;
using Microsoft.AspNetCore.Identity;
using ProyectoFinal.CORE;

namespace ProyectoFinal.DAL
{
    public class DataInitializer
    {


        public static void SeedData(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            SeedRoles(roleManager);
            SeedUsers(userManager);
        }

        private static void SeedUsers(UserManager<ApplicationUser> userManager)
        {
            if (userManager.FindByEmailAsync("admin@proyectofinal.com").Result == null)
            {
                ApplicationUser user = new ApplicationUser();
                user.UserName = "admin@proyectofinal.com";
                user.Email = "admin@proyectofinal.com";

                IdentityResult result = userManager.CreateAsync(user, "1A2B3C4d.").Result;

                if (result.Succeeded)
                {
                    userManager.AddToRoleAsync(user, "Admin").Wait();
                }
            }

        }

        private static void SeedRoles(RoleManager<IdentityRole> roleManager)
        {
            if (!roleManager.RoleExistsAsync("Admin").Result)
            {
                IdentityRole role = new IdentityRole();
                role.Name = "Admin";
                IdentityResult roleResult = roleManager.
                CreateAsync(role).Result;
            }


            if (!roleManager.RoleExistsAsync("Registered").Result)
            {
                IdentityRole role = new IdentityRole();
                role.Name = "Registered";
                IdentityResult roleResult = roleManager.
                CreateAsync(role).Result;
            }


            if (!roleManager.RoleExistsAsync("Professional").Result)
            {
                IdentityRole role = new IdentityRole();
                role.Name = "Professional";
                IdentityResult roleResult = roleManager.
                CreateAsync(role).Result;
            }


            if (!roleManager.RoleExistsAsync("Business").Result)
            {
                IdentityRole role = new IdentityRole();
                role.Name = "Business";
                IdentityResult roleResult = roleManager.
                CreateAsync(role).Result;
            }
        }
    }
}

