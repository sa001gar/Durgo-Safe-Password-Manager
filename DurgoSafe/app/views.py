from django.shortcuts import render, redirect 
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import PasswordManager, CustomUser  # Ensure this imports your custom user model
from cryptography.fernet import Fernet

from django.contrib.auth.hashers import make_password
# password_encryption.py Module in App Directory (DurgoSafe/app/password_encryption.py)
from .password_encryption import generate_key, encrypt_password, decrypt_password

def home(request):
    return render(request, 'welcome_page.html')

from django.contrib.auth.models import Group

def register(request):
    # Check if user is already authenticated
    if request.user.is_authenticated:
        return redirect('profile')
    
    elif request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            # Generate a Fernet key for the user
            master_key = Fernet.generate_key().decode()  # Store as a string
            
            # Create a new user
            user = CustomUser.objects.create_user(
                first_name=first_name, 
                last_name=last_name, 
                email=email, 
                username=username, 
                password=password,
                master_key=master_key  # Store the generated master key in the user model
            )
            
            # Assign the user to the "regular_user" group
            regular_user_group = Group.objects.get(name='regular_user')
            user.groups.add(regular_user_group)
            
            # Log in the user automatically
            login(request, user)
            messages.success(request, 'Account created successfully! You are now logged in as a regular user.')
            return redirect('profile')
        else:
            messages.error(request, 'Passwords do not match')

    return render(request, 'register.html')


def login_user(request):
    # Check if user is already authenticated
    if request.user.is_authenticated:
        # Redirect admin users to the admin page
        if request.user.is_superuser or request.user.is_staff:
            return redirect('logout')  # Redirecting to the admin page
        return redirect('profile')  # Redirect regular users to their profile

    # Handle POST request for login
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Authenticate the user
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.is_superuser or user.is_staff:
                # Admin users are redirected to the admin page upon successful login
                return redirect('logout')  # Redirecting to the admin page
            else:
                login(request, user)
                return redirect('profile')  # Redirect to profile for regular users
        else:
            messages.error(request, 'Invalid credentials')

    return render(request, 'login.html')

@login_required
def profile(request):
    return render(request, 'profile.html', {'user': request.user})

@login_required
def logout_user(request):
    logout(request)
    return redirect('login')

from django.contrib import messages
from django.shortcuts import render, redirect
from cryptography.fernet import Fernet
from .models import PasswordManager

@login_required
def add_password(request):
    if request.method == 'POST':
        domain = request.POST['domain']
        username = request.POST['username']
        password = request.POST['password']
        master_key = request.user.master_key.encode()  # Get the user's master key

        # Encrypt the password
        fernet = Fernet(master_key)
        encrypted_password = fernet.encrypt(password.encode()).decode()  # Encrypt and decode to store as a string

        # Save the password in the PasswordManager
        PasswordManager.objects.create(user=request.user, domain=domain, username=username, password=encrypted_password)
        messages.success(request, 'Password added successfully!')
        return redirect('view_passwords')  # Redirect to view passwords page

    return render(request, 'add_password.html')


@login_required
def view_passwords(request):
    credentials = []  # Initialize an empty list for credentials

    if request.method == 'POST':
        entered_master_key = request.POST.get('master_key')  # Get the master key from the form

        # Ensure the user has a master key set
        if not request.user.master_key:
            messages.error(request, 'No master key set for your account!')
            return render(request, 'view_passwords.html', {'credentials': credentials})

        fernet = Fernet(request.user.master_key.encode())  # Create Fernet object with user's master key

        try:
            # Attempt to decrypt a dummy string to check the key
            fernet.decrypt(entered_master_key.encode())  # Validate the entered master key

            # Fetch the user's credentials
            credentials = PasswordManager.objects.filter(user=request.user)

            # Decrypt passwords for display
            for credential in credentials:
                credential.password = fernet.decrypt(credential.password.encode()).decode()  # Decrypt password

        except Exception as e:
            messages.error(request, f'Invalid master key! Error: {str(e)}')
            return render(request, 'view_passwords.html', {'credentials': credentials})

    # Render the view passwords page
    return render(request, 'view_passwords.html', {'credentials': credentials})


@login_required
def delete_password(request, pk):
    try:
        credential = PasswordManager.objects.get(id=pk, user=request.user)  # Ensure user owns the password
        credential.delete()
        messages.success(request, 'Password deleted successfully!')
    except PasswordManager.DoesNotExist:
        messages.error(request, 'Password entry not found.')

    return redirect('view_passwords')
