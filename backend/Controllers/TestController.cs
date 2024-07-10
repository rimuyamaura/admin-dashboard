using backend.Core.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net.NetworkInformation;

namespace backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet]
        [Route("get-public")]
        public IActionResult GetPublicData()
        {
            return Ok("This is public data");
        }

        [HttpGet]
        [Route("get-user-role")]
        [Authorize(Roles = StaticUserRoles.USER)]

        public IActionResult GetUserData()
        {
            return Ok("User role data");
        }

        [HttpGet]
        [Route("get-manager-role")]
        [Authorize(Roles = StaticUserRoles.MANAGER)]

        public IActionResult GetManagerData()
        {
            return Ok("Manager role data");
        }

        [HttpGet]
        [Route("get-admin-role")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]

        public IActionResult GetAdminData()
        {
            return Ok("Admin role data");
        }

        [HttpGet]
        [Route("get-owner-role")]
        [Authorize(Roles = StaticUserRoles.OWNER)]

        public IActionResult GetOwnerData()
        {
            return Ok("Owner role data");
        }
    }
}
