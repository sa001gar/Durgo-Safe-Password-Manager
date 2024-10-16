from django.shortcuts import render, redirect 
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from .models import password_manager

def register(request):
    if request.user.is_authenticated:
        return redirect('profile')
    elif request.method == 'POST':
        form = UserCreationForm(request.POST)
        first_name=request.POST['first_name']
        last_name=request.POST['last_name']
        email=request.POST['email']
        username=request.POST['username']
        password=request.POST['password1']
        confirm_password=request.POST['password2']
        if password == confirm_password:
            User.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            messages.success(request, 'Account created successfully!')
            return redirect('login')
        else:
            mesasaes.error(request, 'Passwords do not match')
            form = UserCreationForm()
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

def login_user(request):
    if request.user.is_authenticated:
        return redirect('profile')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('profile')
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

@login_required
def add_password(request):
    if request.method == 'POST':
        domain = request.POST['domain']
        username = request.POST['username']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            password_manager.objects.create(user=request.user, domain=domain, username=username, password=password, confirm_password=confirm_password)
            messages.success(request, 'Password added successfully!')
            return redirect('profile')
        else:
            messages.error(request, 'Passwords do not match')

    return render(request, 'add_password.html')


@login_required
def view_passwords(request):
    if request.user.is_authenticated:
        # Fetch credentials for the logged-in user
        credentials = password_manager.objects.filter(user=request.user)
        return render(request, 'view_passwords.html', {'credentials': credentials})
    else:
        return redirect('login') 

@login_required
def delete_password(request, pk):
    credential = password_manager.objects.get(id=pk)
    credential.delete()
    return redirect('view_passwords')