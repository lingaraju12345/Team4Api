namespace User.Management.API.NewFolder
{
    public interface IEmailSender
    {
        Task sendEmail(string email,string subject,string message);
    }
}
