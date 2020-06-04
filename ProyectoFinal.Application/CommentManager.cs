using System;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;

namespace ProyectoFinal.Application
{
    public class CommentManager: GenericManager<Comment>, ICommentManager
    {
        /// <summary>
        /// Constructor de commentmanager
        /// </summary>
        /// <param name="context"></param>
        public CommentManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
