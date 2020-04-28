using System;
using System.Collections.Generic;

namespace ProyectoFinal.IFR.Email
{
    public interface IEmailService
    {
        void Send(EmailMessage emailMessage);
        
    }
}
