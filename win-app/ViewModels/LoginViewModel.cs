using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace win_app.ViewModels;

public class LoginViewModel : INotifyPropertyChanged
{
    private string email;
    private string password;

    public string Email
    {
        get => email;
        set
        {
            if (email == value) return;
            email = value;
            OnPropertyChanged();
        }
    }

    public string Password
    {
        get => password;
        set
        {
            if (password == value) return;
            password = value;
            OnPropertyChanged();
        }
    }
    
    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}