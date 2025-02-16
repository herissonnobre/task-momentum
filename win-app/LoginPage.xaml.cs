using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System.Text.RegularExpressions;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace win_app
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class LoginPage : Page
    {
        public LoginPage()
        {
            this.InitializeComponent();
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            string email = EmailTextBox.Text.Trim();
            string senha = PasswordBox.Password.Trim();

            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(senha))
            {
                await ShowErrorMessage("E-mail e senha são obrigatórios.");
                return;
            }

            if (!IsValidEmail(email))
            {
                await ShowErrorMessage("Digite um e-mail válido.");
                return;
            }

            bool loginSucesso = SimularAutenticacao(email, senha);

            if (loginSucesso)
            {
                // Navegar para a próxima página após login bem-sucedido
                //Frame.Navigate(typeof(HomePage)); // Substitua por sua página de destino
            }
            else
            {
                await ShowErrorMessage("Credenciais inválidas.");
            }
        }

        private async System.Threading.Tasks.Task ShowErrorMessage(string message)
        {
            ContentDialog errorDialog = new ContentDialog
            {
                Title = "Erro",
                Content = message,
                CloseButtonText = "OK",
                XamlRoot = this.XamlRoot
            };
            await errorDialog.ShowAsync();
        }

        private bool IsValidEmail(string email)
        {
            return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        private bool SimularAutenticacao(string email, string senha)
        {
            return email == "user@example.com" && senha == "senha123";
        }
    }
}
