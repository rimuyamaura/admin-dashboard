using backend.Core.Constants;
using backend.Core.Dtos.Auth;
using backend.Core.Dtos.General;
using backend.Core.Interfaces;
using backend.Core.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

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

        public async Task<LoginServiceResponseDto?> LoginAsync(LoginDto loginDto)
        {
            // Check user details
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user is null)
                return null;
            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!isPasswordCorrect)
                return null;

            // Generate token and user info
            var newToken = await GenerateJWTTokenAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var userInfo = GenerateUserInfoObject(user, roles);
            await _logService.SaveNewLog(user.UserName, "User logged in to the system");

            return new LoginServiceResponseDto()
            {
                NewToken = newToken,
                UserInfo = userInfo
            };

        }

        public async Task<GeneralServiceResponseDto> UpdateRoleAsync(ClaimsPrincipal User, UpdateRoleDto updateRoleDto)
        {
            var user = await _userManager.FindByNameAsync(updateRoleDto.UserName);
            if (user is null)
                return new GeneralServiceResponseDto()
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = "Invalid UserName"
                };
            var userRoles = await _userManager.GetRolesAsync(user);

            // OWNER AND ADMIN can update roles
            if(User.IsInRole(StaticUserRoles.ADMIN))
            {
                if(updateRoleDto.NewRole == RoleType.USER || updateRoleDto.NewRole == RoleType.MANAGER)
                {
                    // ADMIN cannot update current OWNER or ADMIN's roles
                    if (userRoles.Any(q => q.Equals(StaticUserRoles.OWNER) || q.Equals(StaticUserRoles.ADMIN)))
                    {
                        return new GeneralServiceResponseDto()
                        {
                            IsSuccess = false,
                            StatusCode = 403,
                            Message = "You are not authorized to update this user's role"
                        };
                    }
                    else
                    {
                        await _userManager.RemoveFromRolesAsync(user, userRoles);
                        await _userManager.AddToRoleAsync(user, updateRoleDto.NewRole.ToString());
                        await _logService.SaveNewLog(user.UserName, "Role updated to " + updateRoleDto.NewRole.ToString());
                        return new GeneralServiceResponseDto()
                        {
                            IsSuccess = true,
                            StatusCode = 200,
                            Message = "Role updated successfully"
                        };
                    }
                }
                else return new GeneralServiceResponseDto()
                {
                    IsSuccess = false,
                    StatusCode = 403,
                    Message = "You are not authorized to update this user's role"
                };
            }
            else
            {
                // OWNER cannot update current OWNER's role
                if (userRoles.Any(q => q.Equals(StaticUserRoles.OWNER)))
                {
                    return new GeneralServiceResponseDto()
                    {
                        IsSuccess = false,
                        StatusCode = 403,
                        Message = "You are not authorized to update this user's role"
                    };
                }
                else
                {
                    await _userManager.RemoveFromRolesAsync(user, userRoles);
                    await _userManager.AddToRoleAsync(user, updateRoleDto.NewRole.ToString());
                    await _logService.SaveNewLog(user.UserName, "Role updated to " + updateRoleDto.NewRole.ToString());
                    return new GeneralServiceResponseDto()
                    {
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = "Role updated successfully"
                    };
                }
            }
        }

        public async Task<LoginServiceResponseDto?> MeAsync(MeDto meDto)
        {
            ClaimsPrincipal handler = new JwtSecurityTokenHandler().ValidateToken(meDto.Token, new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER"),
                ValidAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE"),
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET")))
            }, out SecurityToken securityToken);

            string decodedUserName = handler.Claims.FirstOrDefault(q => q.Type == ClaimTypes.Name).Value;
            if(decodedUserName is null)
                return null;
            
            var user = await _userManager.FindByNameAsync(decodedUserName);
            if (user is null)
                return null;

            var newToken = await GenerateJWTTokenAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var userInfo = GenerateUserInfoObject(user, roles);
            await _logService.SaveNewLog(user.UserName, "New Token Generated");

            return new LoginServiceResponseDto()
            {
                NewToken = newToken,
                UserInfo = userInfo
            };
        }

        public async Task<IEnumerable<UserInfoResult>> GetUsersAsync()
        {
            var users = await _userManager.Users.ToListAsync();

            List<UserInfoResult> userInfoResults = new List<UserInfoResult>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var userInfo = GenerateUserInfoObject(user, roles);
                userInfoResults.Add(userInfo);
            }
            return userInfoResults;
        }

        public async Task<UserInfoResult?> GetUserDetailsByUserNameAsync(string UserName)
        {
            var user = await _userManager.FindByNameAsync(UserName);
            if (user is null)
                return null;

            var roles = await _userManager.GetRolesAsync(user);
            var userInfo = GenerateUserInfoObject(user, roles);
            return userInfo;
        }

        public async Task<IEnumerable<string>> GetUserNamesListAsync()
        {
            var userNames = await _userManager.Users
                .Select(q => q.UserName)
                .ToListAsync();

            return userNames;
        }



        // Helper methods
        private async Task<string> GenerateJWTTokenAsync(User user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET")));
            var signingCredentials = new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256);

            var tokenObject = new JwtSecurityToken(
                issuer: Environment.GetEnvironmentVariable("JWT_ISSUER"),
                audience: Environment.GetEnvironmentVariable("JWT_AUDIENCE"),
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: signingCredentials
            );

            string tokenString = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return tokenString;
        }

        private UserInfoResult GenerateUserInfoObject(User user, IEnumerable<string> roles)
        {
            return new UserInfoResult()
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                UserName = user.UserName,
                Email = user.Email,
                CreatedAt = user.CreatedAt,
                Roles = roles
            };
        }
    }
}
