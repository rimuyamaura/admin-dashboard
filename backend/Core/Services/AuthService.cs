using backend.Core.Constants;
using backend.Core.Dtos.Auth;
using backend.Core.Dtos.General;
using backend.Core.Interfaces;
using backend.Core.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace backend.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogService _logService;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, ILogService logService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logService = logService;
            _configuration = configuration;
        }

        public async Task<GeneralServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isManagerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.MANAGER);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isManagerRoleExists && isUserRoleExists)
                return new GeneralServiceResponseDto()
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = "Role seeding is already complete"
                };

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.MANAGER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));

            return new GeneralServiceResponseDto()
            {
                IsSuccess = true,
                StatusCode = 201,
                Message = "Role seeding completed successfully"
            };
        }
        public async Task<GeneralServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isUserExists = await _userManager.FindByNameAsync(registerDto.UserName);
            if (isUserExists is not null)
                return new GeneralServiceResponseDto()
                {
                    IsSuccess = false,
                    StatusCode = 409,
                    Message = "User already exists"
                };
            User newUser = new User()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                Address = registerDto.Address,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);
            if (!createUserResult.Succeeded)
            {
                var errorString = "User creation failed: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += "#" + error.Description;
                }
                return new GeneralServiceResponseDto()
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = errorString
                };
            }

            // Add default USER role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
            await _logService.SaveNewLog(newUser.UserName, "User registered to the system");

            return new GeneralServiceResponseDto()
            {
                IsSuccess = true,
                StatusCode = 201,
                Message = "User created successfully"
            };
        }

        public Task<UserInfoResult> GetUserDetailsByUserName(string UserName)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<string>> GetUserNamesListAsync()
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<UserInfoResult>> GetUsersAsync()
        {
            throw new NotImplementedException();
        }

        public Task<LoginServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            throw new NotImplementedException();
        }

        public Task<LoginServiceResponseDto> MeAsync(MeDto meDto)
        {
            throw new NotImplementedException();
        }

        

        

        public Task<GeneralServiceResponseDto> UpdateRoleAsync(ClaimsPrincipal User, UpdateRoleDto updateRoleDto)
        {
            throw new NotImplementedException();
        }
    }
}
