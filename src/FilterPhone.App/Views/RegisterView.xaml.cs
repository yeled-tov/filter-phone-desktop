using System.ComponentModel;

namespace FilterPhone.App.Views;

public partial class RegisterView
{
    public RegisterView()
    {
        InitializeComponent();
        // Each step starts at the top.
        DataContextChanged += (_, e) =>
        {
            if (e.NewValue is INotifyPropertyChanged vm)
            {
                vm.PropertyChanged += (_, p) =>
                {
                    if (p.PropertyName == nameof(RegistrationViewModel.Step))
                    {
                        Scroll.ScrollToTop();
                    }
                };
            }
        };
    }
}
