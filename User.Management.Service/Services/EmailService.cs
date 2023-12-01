using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using User.Management.Service.Models;

namespace User.Management.Service.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailConfiguration _emailConfig;
        public EmailService(EmailConfiguration emailConfig) => _emailConfig = emailConfig;
        public void SendEmail(Message message)
        {
            var emailMessage = CreateEmailMessage(message);
            Send(emailMessage);
        }

        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("email", _emailConfig.From));
            
            emailMessage.To.AddRange(message.To);
            
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message.Content };

            return emailMessage;
        }

        private void Send(MimeMessage mailMessage)
        {
            using var smtp = new MailKit.Net.Smtp.SmtpClient();
            smtp.CheckCertificateRevocation = false;
            try
            {

                
                
                smtp.Connect(_emailConfig.SmtpServer, _emailConfig.Port, SecureSocketOptions.StartTls);
                
                smtp.Authenticate(_emailConfig.UserName, _emailConfig.Password);
                smtp.Send(mailMessage);

            }
            catch
            {
                //log an error message or throw an exception or both.
                throw;
            }
            finally
            {
                smtp.Disconnect(true);
                smtp.Dispose();
            }
        }
        
    }
}
