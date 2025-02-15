using System.Windows;
using System.Windows.Controls;

namespace win_app.Views;

public partial class LoginPage : Page
{
    public LoginPage()
    {
        InitializeComponent();
    }

    private void LoginButton_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        string email = EmailTextBox.Text;
        string password = PasswordBox.Password;

        if (email == "" || password == "")
        {
            MessageBox.Show("Please, enter your email and password.");
        }
        else
        {
            MessageBox.Show("You entered your email and password.");
        }
    }
}