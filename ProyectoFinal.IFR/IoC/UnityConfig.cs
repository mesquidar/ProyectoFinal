using System;
using Unity;

namespace ProyectoFinal.IFR.IoC
{
    /// <summary>
    /// Specifies the Unity configuration for the main container.
    /// </summary>
    public static class UnityConfig
    {
        #region Unity Container
        private static Lazy<IUnityContainer> container = new Lazy<IUnityContainer>(() =>
        {
            var container = new UnityContainer();
            RegisterTypes(container);
            return container;
        });

        /// <summary>
        /// Gets the configured Unity container.
        /// </summary>
        public static IUnityContainer GetConfiguredContainer()
        {
            return container.Value;
        }
        #endregion

        /// <summary>Registers the type mappings with the Unity container.</summary>
        /// <param name="container">The unity container to configure.</param>
        /// <remarks>There is no need to register concrete types such as controllers or API controllers (unless you want to 
        /// change the defaults), as Unity allows resolving a concrete type even if it was not previously registered.</remarks>
        public static void RegisterTypes(IUnityContainer container)
        {

            // TODO: Register your types here
            container.RegisterType<ProyectoFinal.IFR.Log.ILogEvent, ProyectoFinal.IFR.Log.Log4NetManager>();
            //container.RegisterType<ProyectoFinal.IFR.Email.IEmailEvent, ProyectoFinal.IFR.Email.EmailManager>();
            container.RegisterType(Type.GetType("ProyectoFinal.CORE.Contracts.IApplicationDbContext, ProyectoFinal.CORE"), Type.GetType("ProyectoFinal.DAL.ApplicationDbContext, ProyectoFinal.DAL"));

        }
    }
}
