using System.Linq;
using ProyectoFinal.CORE.Contracts;

namespace ProyectoFinal.CORE.Contracts
{
    public interface IGenericManager<T> where T : class
    {
        IApplicationDbContext Context { get; }
        T Add(T entity);
        IQueryable<T> GetAll();
        T GetById(object[] key);
        T GetById(int id);
        T Remove(T entity);
    }
}