namespace ProyectoFinal.Web.Areas.Admin.Models
{
    public class UserList
    {
        /// <summary>
                /// id del usuario
                /// </summary>
                public string Id { get; set; }
        
                /// <summary>
                /// nombre de usuario
                /// </summary>
                public string UserName { get; set; }
        
                /// <summary>
                /// email del usuario
                /// </summary>
                public string Email { get; set; }
        
                /// <summary>
                /// numero de telefono del usuario
                /// </summary>
                public string PhoneNumber { get; set; }
        
                /// <summary>
                /// password del usaurio
                /// </summary>
                public string Password { get; set; }

    }
}